// Package messaging implements the durable outbox/inbox pattern for the Dnivio Approval Service.
// Per §11.5 (DR-SVC-5…6) of ENGINEERING.md v2.1:
// Every security-critical message is written to a transactional outbox before dispatch,
// delivered with ordered sequence numbers + acknowledgement, replayed from cursors,
// and deduplicated by stable message ID.
package messaging

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ─── Outbox ──────────────────────────────────────────────────────────────

// OutboxWriter writes messages to the outbox as part of a database transaction.
type OutboxWriter struct {
	db *sql.DB
}

// NewOutboxWriter creates a new OutboxWriter.
func NewOutboxWriter(db *sql.DB) *OutboxWriter {
	return &OutboxWriter{db: db}
}

// OutboxMessage represents a message to be delivered through the outbox.
type OutboxMessage struct {
	TenantID  uuid.UUID
	Consumer  string    // daemon node_id or device_id
	MessageID uuid.UUID // stable deduplication key
	Payload   []byte    // serialized COSE_Sign1 envelope
}

// WriteTx writes a message to the outbox within an existing transaction.
// The message will be delivered to the consumer via the ordered stream.
func (w *OutboxWriter) WriteTx(ctx context.Context, tx *sql.Tx, msg OutboxMessage) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO outbox (tenant_id, seq, consumer, message_id, payload, created_at)
		VALUES ($1,
			COALESCE((SELECT MAX(seq) FROM outbox WHERE tenant_id = $1 AND consumer = $2), 0) + 1,
			$2, $3, $4, $5)
		ON CONFLICT (tenant_id, message_id) DO NOTHING
	`, msg.TenantID, msg.Consumer, msg.MessageID, msg.Payload, time.Now().UTC())
	return err
}

// ─── Delivery Stream ──────────────────────────────────────────────────────

// DeliveryStream delivers ordered messages to consumers and processes acknowledgements.
type DeliveryStream struct {
	db      *sql.DB
	mu      sync.RWMutex
	watchers map[string]map[string]chan struct{} // tenant -> consumer -> wake channel
}

// NewDeliveryStream creates a new DeliveryStream.
func NewDeliveryStream(db *sql.DB) *DeliveryStream {
	return &DeliveryStream{
		db:      db,
		watchers: make(map[string]map[string]chan struct{}),
	}
}

// ConsumerLease represents a leased delivery session for a consumer.
type ConsumerLease struct {
	TenantID    uuid.UUID
	Consumer    string
	LeaseOwner  uuid.UUID
	LeaseFence  int64
	ExpiresAt   time.Time
	LastAckedSeq int64
}

// AcquireLease acquires or renews a consumer lease with fencing (DR-SVC-1).
// Returns the lease and the next sequence number to deliver.
func (ds *DeliveryStream) AcquireLease(ctx context.Context, tenantID uuid.UUID, consumer string, owner uuid.UUID) (*ConsumerLease, error) {
	tx, err := ds.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("messaging: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Atomically increment fence and set lease owner
	var lastAckedSeq int64
	var fence int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO consumer_cursors (tenant_id, consumer, last_acked_seq, lease_owner, lease_fence, lease_expires_at)
		VALUES ($1, $2, 0, $3, 1, $4)
		ON CONFLICT (tenant_id, consumer) DO UPDATE
		SET lease_owner = $3,
		    lease_fence = consumer_cursors.lease_fence + 1,
		    lease_expires_at = $4
		RETURNING last_acked_seq, lease_fence
	`, tenantID, consumer, owner, time.Now().UTC().Add(15*time.Second)).Scan(&lastAckedSeq, &fence)
	if err != nil {
		return nil, fmt.Errorf("messaging: acquire lease: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("messaging: commit lease: %w", err)
	}

	return &ConsumerLease{
		TenantID:     tenantID,
		Consumer:     consumer,
		LeaseOwner:   owner,
		LeaseFence:   fence,
		ExpiresAt:    time.Now().UTC().Add(15 * time.Second),
		LastAckedSeq: lastAckedSeq,
	}, nil
}

// RenewLease renews an existing consumer lease. Must match the current lease fence.
func (ds *DeliveryStream) RenewLease(ctx context.Context, lease *ConsumerLease) error {
	result, err := ds.db.ExecContext(ctx, `
		UPDATE consumer_cursors
		SET lease_expires_at = $1
		WHERE tenant_id = $2
		  AND consumer = $3
		  AND lease_fence = $4
		  AND lease_expires_at > now()
	`, time.Now().UTC().Add(15*time.Second), lease.TenantID, lease.Consumer, lease.LeaseFence)
	if err != nil {
		return fmt.Errorf("messaging: renew lease: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("messaging: lease renewal failed — fence mismatch or expired")
	}
	lease.ExpiresAt = time.Now().UTC().Add(15 * time.Second)
	return nil
}

// FetchPending returns undelivered messages for a consumer starting from last_acked_seq+1.
func (ds *DeliveryStream) FetchPending(ctx context.Context, tenantID uuid.UUID, consumer string, fromSeq int64, limit int) ([]OutboxMessage, error) {
	rows, err := ds.db.QueryContext(ctx, `
		SELECT tenant_id, consumer, message_id, payload, seq
		FROM outbox
		WHERE tenant_id = $1
		  AND consumer = $2
		  AND seq > $3
		  AND acked_at IS NULL
		ORDER BY seq ASC
		LIMIT $4
	`, tenantID, consumer, fromSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("messaging: fetch pending: %w", err)
	}
	defer rows.Close()

	var messages []OutboxMessage
	for rows.Next() {
		var msg OutboxMessage
		var seq int64
		if err := rows.Scan(&msg.TenantID, &msg.Consumer, &msg.MessageID, &msg.Payload, &seq); err != nil {
			return nil, fmt.Errorf("messaging: scan message: %w", err)
		}
		messages = append(messages, msg)
	}
	return messages, rows.Err()
}

// AckMessage acknowledges delivery of a message (DR-SVC-5).
// Deduplicates by message_id via the inbox table.
func (ds *DeliveryStream) AckMessage(ctx context.Context, tenantID uuid.UUID, consumer string, messageID uuid.UUID, seq int64, fence int64) (bool, error) {
	tx, err := ds.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("messaging: begin ack tx: %w", err)
	}
	defer tx.Rollback()

	// Verify fence ownership
	var currentFence int64
	err = tx.QueryRowContext(ctx, `
		SELECT lease_fence FROM consumer_cursors
		WHERE tenant_id = $1 AND consumer = $2
		FOR UPDATE
	`, tenantID, consumer).Scan(&currentFence)
	if err != nil {
		return false, fmt.Errorf("messaging: check fence: %w", err)
	}
	if currentFence != fence {
		return false, fmt.Errorf("messaging: stale fence — ack rejected")
	}

	// Deduplicate via inbox
	var alreadyProcessed bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM inbox
			WHERE tenant_id = $1 AND consumer = $2 AND message_id = $3
		)
	`, tenantID, consumer, messageID).Scan(&alreadyProcessed)
	if err != nil {
		return false, fmt.Errorf("messaging: check inbox: %w", err)
	}

	if !alreadyProcessed {
		// Mark outbox message as acked
		_, err = tx.ExecContext(ctx, `
			UPDATE outbox SET acked_at = now()
			WHERE tenant_id = $1 AND consumer = $2 AND seq = $3
		`, tenantID, consumer, seq)
		if err != nil {
			return false, fmt.Errorf("messaging: ack outbox: %w", err)
		}

		// Record in inbox for deduplication
		_, err = tx.ExecContext(ctx, `
			INSERT INTO inbox (tenant_id, consumer, message_id)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, consumer, message_id) DO NOTHING
		`, tenantID, consumer, messageID)
		if err != nil {
			return false, fmt.Errorf("messaging: record inbox: %w", err)
		}

		// Advance cursor
		_, err = tx.ExecContext(ctx, `
			UPDATE consumer_cursors
			SET last_acked_seq = GREATEST(last_acked_seq, $1)
			WHERE tenant_id = $2 AND consumer = $3
		`, seq, tenantID, consumer)
		if err != nil {
			return false, fmt.Errorf("messaging: advance cursor: %w", err)
		}
	}

	return !alreadyProcessed, tx.Commit()
}

// ReleaseLease releases a consumer lease (graceful shutdown).
func (ds *DeliveryStream) ReleaseLease(ctx context.Context, lease *ConsumerLease) error {
	_, err := ds.db.ExecContext(ctx, `
		UPDATE consumer_cursors
		SET lease_owner = NULL, lease_expires_at = NULL
		WHERE tenant_id = $1
		  AND consumer = $2
		  AND lease_fence = $3
	`, lease.TenantID, lease.Consumer, lease.LeaseFence)
	return err
}

// NotifyConsumer sends a wake-up notification to any watcher for a consumer.
// Uses Postgres LISTEN/NOTIFY as a hint only (ADR-006).
func (ds *DeliveryStream) NotifyConsumer(ctx context.Context, tenantID uuid.UUID, consumer string) error {
	key := fmt.Sprintf("%s/%s", tenantID.String(), consumer)
	_, err := ds.db.ExecContext(ctx, fmt.Sprintf("NOTIFY %s", key))
	if err != nil {
		// Notify is best-effort; core delivery uses the outbox
		return nil
	}
	return nil
}

// ─── Message Types ────────────────────────────────────────────────────────

// MessageType identifies the type of outbox message.
type MessageType string

const (
	MessageTypeGrant              MessageType = "GRANT"
	MessageTypeDenial             MessageType = "DENIAL"
	MessageTypeCancellation       MessageType = "CANCELLATION"
	MessageTypePolicyUpdate       MessageType = "POLICY_UPDATE"
	MessageTypeRevocation         MessageType = "REVOCATION"
	MessageTypeBreakGlassGrant    MessageType = "BREAKGLASS_GRANT"
)

// Envelope is the wrapper for all outbox-delivered messages.
type Envelope struct {
	Type      MessageType `json:"type"`
	MessageID uuid.UUID   `json:"message_id"`
	Seq       int64       `json:"seq"`
	Payload   []byte      `json:"payload"` // COSE_Sign1 serialized content
	CreatedAt time.Time   `json:"created_at"`
}
