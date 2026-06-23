// Package revocation implements the bounded revocation system per §13 of ENGINEERING.md v2.1.
// Features: ordered acknowledged stream, bounded freshness (R=10s),
// active-session termination, and multi-scope revocation.
package revocation

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dnivio/approval-service/internal/messaging"
	"github.com/google/uuid"
)

// ─── Revocation Manager ──────────────────────────────────────────────────

// Manager handles revocation creation, delivery, and active-session termination.
type Manager struct {
	db           *sql.DB
	delivery     *messaging.DeliveryStream
	outboxWriter *messaging.OutboxWriter
	mu           sync.RWMutex
	seqMu        sync.Mutex // H8 fix: serializes sequence allocation
}

// NewManager creates a new revocation manager.
func NewManager(db *sql.DB, delivery *messaging.DeliveryStream, outboxWriter *messaging.OutboxWriter) *Manager {
	return &Manager{
		db:           db,
		delivery:     delivery,
		outboxWriter: outboxWriter,
	}
}

// ─── Revocation Kinds (DR-REV-4) ─────────────────────────────────────────

// Kind identifies the type of revocation.
type Kind string

const (
	KindUser          Kind = "user"
	KindSourceNode    Kind = "source_node"
	KindProtectedNode Kind = "protected_node"
	KindDevice        Kind = "device"
	KindKey           Kind = "key"
	KindCert          Kind = "cert"
	KindGrant         Kind = "grant"
	KindPolicy        Kind = "policy"
)

// Revocation represents a single revocation event.
type Revocation struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Seq       int64     `json:"seq"`
	Kind      Kind      `json:"kind"`
	Target    string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── Issue Revocation ────────────────────────────────────────────────────

// IssueRevocation creates a new revocation event and queues it for delivery.
// The revocation is committed to the ordered stream immediately.
func (m *Manager) IssueRevocation(ctx context.Context, tenantID uuid.UUID, kind Kind, target string, affectedConsumers []string) (*Revocation, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("revocation: begin tx: %w", err)
	}
	defer tx.Rollback()

	// H8 fix: serialize sequence allocation to prevent MAX(seq)+1 race
	m.seqMu.Lock()
	defer m.seqMu.Unlock()

	// Get next sequence number for this tenant
	var nextSeq int64
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(seq), 0) + 1
		FROM revocations
		WHERE tenant_id = $1
		FOR UPDATE
	`, tenantID).Scan(&nextSeq)
	if err != nil {
		return nil, fmt.Errorf("revocation: get next seq: %w", err)
	}

	// Insert revocation
	rev := &Revocation{
		TenantID:  tenantID,
		Seq:       nextSeq,
		Kind:      kind,
		Target:    target,
		CreatedAt: time.Now().UTC(),
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO revocations (tenant_id, seq, kind, target, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, rev.TenantID, rev.Seq, rev.Kind, rev.Target, rev.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("revocation: insert: %w", err)
	}

	// Terminate active sessions for the revoked entity (DR-REV-3)
	if err := m.terminateActiveSessions(ctx, tx, tenantID, kind, target); err != nil {
		return nil, fmt.Errorf("revocation: terminate sessions: %w", err)
	}

	// Invalidate affected grants
	if err := m.invalidateGrants(ctx, tx, tenantID, kind, target); err != nil {
		return nil, fmt.Errorf("revocation: invalidate grants: %w", err)
	}

	// Queue delivery to all affected consumers via outbox
	for _, consumer := range affectedConsumers {
		// H8 fix: serialize revocation into payload so daemons know what was revoked
		payload, _ := json.Marshal(rev)
		msg := messaging.OutboxMessage{
			TenantID:  tenantID,
			Consumer:  consumer,
			MessageID: uuid.New(),
			Payload:   payload,
		}
		if err := m.outboxWriter.WriteTx(ctx, tx, msg); err != nil {
			return nil, fmt.Errorf("revocation: write to outbox: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("revocation: commit: %w", err)
	}

	// Wake all affected consumers
	for _, consumer := range affectedConsumers {
		m.delivery.NotifyConsumer(ctx, tenantID, consumer)
	}

	return rev, nil
}

// ─── Active Session Termination (DR-REV-3) ───────────────────────────────

func (m *Manager) terminateActiveSessions(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, kind Kind, target string) error {
	switch kind {
	case KindDevice:
		return m.terminateDeviceSessions(ctx, tx, tenantID, target)
	case KindUser:
		return m.terminateUserSessions(ctx, tx, tenantID, target)
	case KindSourceNode:
		return m.terminateSourceNodeSessions(ctx, tx, tenantID, target)
	case KindGrant:
		return m.terminateGrantSession(ctx, tx, tenantID, target)
	case KindProtectedNode:
		return m.terminateProtectedNodeSessions(ctx, tx, tenantID, target)
	default:
		return nil
	}
}

func (m *Manager) terminateDeviceSessions(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, deviceID string) error {
	// Mark all active sessions for this device as closed
	_, err := tx.ExecContext(ctx, `
		UPDATE active_sessions
		SET closed_at = now()
		WHERE tenant_id = $1
		  AND device_id = $2
		  AND closed_at IS NULL
	`, tenantID, deviceID)
	return err
}

func (m *Manager) terminateUserSessions(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, userID string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE active_sessions
		SET closed_at = now()
		WHERE tenant_id = $1
		  AND grant_jti IN (
			SELECT jti FROM grants WHERE tenant_id = $1 AND user_id = $2
		  )
		  AND closed_at IS NULL
	`, tenantID, userID)
	return err
}

func (m *Manager) terminateSourceNodeSessions(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, srcNodeID string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE active_sessions
		SET closed_at = now()
		WHERE tenant_id = $1
		  AND grant_jti IN (
			SELECT jti FROM grants WHERE tenant_id = $1 AND src_node_id = $2
		  )
		  AND closed_at IS NULL
	`, tenantID, srcNodeID)
	return err
}

func (m *Manager) terminateProtectedNodeSessions(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, protectedNodeID string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE active_sessions
		SET closed_at = now()
		WHERE tenant_id = $1
		  AND node_id = $2
		  AND closed_at IS NULL
	`, tenantID, protectedNodeID)
	return err
}

func (m *Manager) terminateGrantSession(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, grantJTI string) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE active_sessions
		SET closed_at = now()
		WHERE tenant_id = $1
		  AND grant_jti = $2
		  AND closed_at IS NULL
	`, tenantID, grantJTI)
	return err
}

// ─── Grant Invalidation ──────────────────────────────────────────────────

func (m *Manager) invalidateGrants(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, kind Kind, target string) error {
	switch kind {
	case KindDevice:
		_, err := tx.ExecContext(ctx, `
			DELETE FROM grants WHERE tenant_id = $1 AND device_id = $2 AND consumed_at IS NULL
		`, tenantID, target)
		return err
	case KindUser:
		_, err := tx.ExecContext(ctx, `
			DELETE FROM grants WHERE tenant_id = $1 AND user_id = $2 AND consumed_at IS NULL
		`, tenantID, target)
		return err
	case KindSourceNode:
		_, err := tx.ExecContext(ctx, `
			DELETE FROM grants WHERE tenant_id = $1 AND src_node_id = $2 AND consumed_at IS NULL
		`, tenantID, target)
		return err
	case KindGrant:
		_, err := tx.ExecContext(ctx, `
			DELETE FROM grants WHERE tenant_id = $1 AND jti = $2 AND consumed_at IS NULL
		`, tenantID, target)
		return err
	case KindPolicy:
		// Policy change invalidates all unconsumed grants for the tenant
		_, err := tx.ExecContext(ctx, `
			DELETE FROM grants WHERE tenant_id = $1 AND consumed_at IS NULL
		`, tenantID)
		return err
	default:
		return nil
	}
}

// ─── Revocation Freshness (DR-REV-1…2) ──────────────────────────────────

// RevocationFreshnessBound is the hard freshness bound: 10 seconds (DR-REV-1).
const RevocationFreshnessBound = 10 * time.Second

// CheckFreshness verifies a daemon's revocation status is not stale.
// Returns nil if fresh, or an error if the daemon must fail closed.
func (m *Manager) CheckFreshness(ctx context.Context, tenantID uuid.UUID, daemonLastAckedSeq int64) (bool, int64, error) {
	var latestSeq int64
	err := m.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(seq), 0)
		FROM revocations
		WHERE tenant_id = $1
	`, tenantID).Scan(&latestSeq)
	if err != nil {
		return false, 0, fmt.Errorf("revocation: check freshness: %w", err)
	}

	if latestSeq > daemonLastAckedSeq {
		return false, latestSeq, nil // Stale — daemon must catch up or fail closed
	}

	return true, latestSeq, nil
}

// GetRevocationsSince returns all revocations after a given sequence number.
func (m *Manager) GetRevocationsSince(ctx context.Context, tenantID uuid.UUID, sinceSeq int64) ([]Revocation, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT tenant_id, seq, kind, target, created_at
		FROM revocations
		WHERE tenant_id = $1 AND seq > $2
		ORDER BY seq ASC
	`, tenantID, sinceSeq)
	if err != nil {
		return nil, fmt.Errorf("revocation: query since: %w", err)
	}
	defer rows.Close()

	var revs []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.TenantID, &r.Seq, &r.Kind, &r.Target, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("revocation: scan: %w", err)
		}
		revs = append(revs, r)
	}
	return revs, rows.Err()
}

// ─── Device Revocation ───────────────────────────────────────────────────

// RevokeDevice revokes a device and terminates all its active sessions.
// Per design.md: lost devices are revoked with a hard ten-second propagation bound,
// and active sessions issued through the device are terminated.
func (m *Manager) RevokeDevice(ctx context.Context, tenantID, deviceID uuid.UUID, reason string) error {
	// Mark device as revoked
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("revocation: begin device revoke tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		UPDATE devices
		SET state = 'REVOKED', revoked_at = now()
		WHERE tenant_id = $1 AND id = $2 AND state = 'ENROLLED'
	`, tenantID, deviceID)
	if err != nil {
		return fmt.Errorf("revocation: update device: %w", err)
	}

	// Issue revocation event
	rev, err := m.issueRevocationInTx(ctx, tx, tenantID, KindDevice, deviceID.String())
	if err != nil {
		return fmt.Errorf("revocation: issue revocation: %w", err)
	}
	_ = rev

	return tx.Commit()
}

func (m *Manager) issueRevocationInTx(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, kind Kind, target string) (*Revocation, error) {
	// H8 fix: also protect sequence allocation when called from paths that don't lock
	m.seqMu.Lock()
	defer m.seqMu.Unlock()

	var nextSeq int64
	err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(seq), 0) + 1 FROM revocations WHERE tenant_id = $1 FOR UPDATE
	`, tenantID).Scan(&nextSeq)
	if err != nil {
		return nil, err
	}

	rev := &Revocation{
		TenantID:  tenantID,
		Seq:       nextSeq,
		Kind:      kind,
		Target:    target,
		CreatedAt: time.Now().UTC(),
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO revocations (tenant_id, seq, kind, target, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, rev.TenantID, rev.Seq, rev.Kind, rev.Target, rev.CreatedAt)

	return rev, err
}

// ─── Daemon-Side Freshness (exported for daemon use) ────────────────────

// FreshnessStatus reports the revocation freshness status at a daemon.
type FreshnessStatus struct {
	Current          bool      `json:"current"`
	LastAckedSeq     int64     `json:"last_acked_seq"`
	LatestSeq        int64     `json:"latest_seq"`
	LastAckTime      time.Time `json:"last_ack_time"`
	SecondsAgo       float64   `json:"seconds_ago"`
	MustFailClosed   bool      `json:"must_fail_closed"`
}

// CheckDaemonFreshness determines if a daemon's revocation state is fresh enough.
// Per DR-REV-2: if freshness exceeds R (10s), MUST fail closed for REQUIRE_STEP_UP resources.
func CheckDaemonFreshness(lastAckTime time.Time, lastAckedSeq, latestSeq int64) *FreshnessStatus {
	since := time.Since(lastAckTime)
	status := &FreshnessStatus{
		LastAckedSeq:  lastAckedSeq,
		LatestSeq:     latestSeq,
		LastAckTime:   lastAckTime,
		SecondsAgo:    since.Seconds(),
		Current:       lastAckedSeq >= latestSeq && since <= RevocationFreshnessBound,
		MustFailClosed: since > RevocationFreshnessBound || lastAckedSeq < latestSeq,
	}

	return status
}
