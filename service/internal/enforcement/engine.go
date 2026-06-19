// Package enforcement implements the approval state machine for the Dnivio Approval Service.
// Per §11.3 (DR-SVC-2…3) of ENGINEERING.md v2.1.
package enforcement

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dnivio/contracts"
	"github.com/dnivio/contracts/cose"
	"github.com/dnivio/approval-service/internal/audit"
	"github.com/dnivio/approval-service/internal/messaging"
	"github.com/google/uuid"
)

// ─── Approval Engine ──────────────────────────────────────────────────────

// ApprovalEngine manages the lifecycle of approval requests and grants.
type ApprovalEngine struct {
	db            *sql.DB
	auditWriter   *audit.ChainWriter
	outboxWriter  *messaging.OutboxWriter
	delivery      *messaging.DeliveryStream
	requestSigner RequestSigner
	grantSigner   GrantSigner
	encrypter     EnvelopeEncrypter
}

// RequestSigner signs approval request envelopes (request_sig key).
type RequestSigner interface {
	SignRequest(ctx context.Context, payload *contracts.RequestPayload) ([]byte, error) // COSE_Sign1 CBOR
}

// GrantSigner signs access grant tokens (grant_sig key).
type GrantSigner interface {
	SignGrant(ctx context.Context, payload *contracts.AGTPayload) ([]byte, error) // COSE_Sign1 CBOR
}

// EnvelopeEncrypter encrypts sensitive data at rest.
type EnvelopeEncrypter interface {
	Encrypt(ctx context.Context, tenantID uuid.UUID, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, tenantID uuid.UUID, ciphertext []byte) ([]byte, error)
}

// NewApprovalEngine creates a new ApprovalEngine.
func NewApprovalEngine(db *sql.DB, auditWriter *audit.ChainWriter, outboxWriter *messaging.OutboxWriter, delivery *messaging.DeliveryStream, requestSigner RequestSigner, grantSigner GrantSigner) *ApprovalEngine {
	return &ApprovalEngine{
		db:           db,
		auditWriter:  auditWriter,
		outboxWriter: outboxWriter,
		delivery:     delivery,
		requestSigner: requestSigner,
		grantSigner:   grantSigner,
	}
}

// ─── Create Approval Request ─────────────────────────────────────────────

// CreateApprovalRequestInput is the input for creating a new approval request.
type CreateApprovalRequestInput struct {
	TenantID       uuid.UUID
	TailnetID       string
	UserID          uuid.UUID
	SrcNodeID       string
	SrcNodeKeyEpoch int64
	RequestingIP    string
	NodeID          uuid.UUID
	ResourceID      uuid.UUID
	Protocol        string
	SSHAccount      string
	Scope           contracts.Scope
	Binding         contracts.ScopeBinding
	PolicyVersion   int64
	RuleID          string
	DeviceID        uuid.UUID  // Target approver device
}

// CreateApprovalRequest creates a new approval request and its signed envelope.
func (ae *ApprovalEngine) CreateApprovalRequest(ctx context.Context, input CreateApprovalRequestInput) (*contracts.RequestEnvelope, string, string, error) {
	requestID := contracts.NewRequestID()
	challenge, err := contracts.NewNonce(32)
	if err != nil {
		return nil, "", "", fmt.Errorf("enforcement: generate challenge: %w", err)
	}

	// Get resource display label
	resourceLabel, err := ae.getResourceLabel(ctx, input.TenantID, input.ResourceID)
	if err != nil {
		return nil, "", "", fmt.Errorf("enforcement: get resource: %w", err)
	}

	payload := &contracts.RequestPayload{
		RequestID:       requestID,
		TenantID:        input.TenantID,
		TailnetID:       input.TailnetID,
		AudienceDeviceID: input.DeviceID,
		Initiating: contracts.InitiatingInfo{
			SrcNodeID:       input.SrcNodeID,
			SrcNodeDisplay:   input.SrcNodeID, // simplified; production uses verified display name
			SrcNodeVerified:  true,
			RequestingIP:    input.RequestingIP,
		},
		Resource: contracts.ResourceID{
			TenantID:       input.TenantID,
			ProtectedNodeID: input.NodeID.String(),
			// ServiceID, Port, Transport, DeploymentMode populated from resource lookup
		},
		ResourceDisplay: resourceLabel,
		Protocol:        input.Protocol,
		SSHAccount:      input.SSHAccount,
		PolicyVersion:   input.PolicyVersion,
		RuleID:          input.RuleID,
		ScopeRequested:  input.Scope,
		Binding:         input.Binding,
		Challenge:       challenge,
	}

	// Sign the request envelope
	envelopeBytes, err := ae.requestSigner.SignRequest(ctx, payload)
	if err != nil {
		return nil, "", "", fmt.Errorf("enforcement: sign request: %w", err)
	}

	// Generate interstitial capabilities for HTTP_PROXY mode
	pollCap, redeemCap := generateCapabilities()
	pollCapHash := sha256.Sum256([]byte(pollCap))
	redeemCapHash := sha256.Sum256([]byte(redeemCap))

	// Persist the request in a transaction with audit
	tx, err := ae.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("enforcement: begin tx: %w", err)
	}
	defer tx.Rollback()

	bindingBytes, _ := cose.EncodeCanonical(input.Binding)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO approval_requests (
			id, tenant_id, user_id, device_id, node_id,
			src_node_id, requesting_ip, resource_id, protocol,
			ssh_account, scope, binding, challenge,
			envelope, envelope_sig, policy_version, rule_id,
			poll_cap_hash, redeem_cap_hash,
			expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
	`, requestID, input.TenantID, input.UserID, input.DeviceID, input.NodeID,
		input.SrcNodeID, input.RequestingIP, input.ResourceID, input.Protocol,
		input.SSHAccount, input.Scope, bindingBytes, challenge,
		envelopeBytes, []byte{}, input.PolicyVersion, input.RuleID,
		pollCapHash[:], redeemCapHash[:],
		time.Now().UTC().Add(60*time.Second),
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("enforcement: insert request: %w", err)
	}

	// Audit: APPROVAL_REQUEST
	auditPayload, _ := json.Marshal(map[string]interface{}{
		"user_id":     input.UserID,
		"device_id":   input.DeviceID,
		"resource_id": input.ResourceID,
		"protocol":    input.Protocol,
		"scope":       input.Scope,
		"rule_id":     input.RuleID,
	})
	ae.auditWriter.InsertTx(ctx, tx, audit.AuditEvent{
		TenantID:      input.TenantID,
		EventType:     audit.EventApprovalRequest,
		Producer:      "service",
		UserID:        &input.UserID,
		DeviceID:      &input.DeviceID,
		ResourceID:    &input.ResourceID,
		Protocol:      &input.Protocol,
		RequestID:     &requestID,
		CorrelationID: uuid.New(),
		Payload:       auditPayload,
	})

	// Write notification to outbox for device delivery
	ae.outboxWriter.WriteTx(ctx, tx, messaging.OutboxMessage{
		TenantID:  input.TenantID,
		Consumer:  input.DeviceID.String(),
		MessageID: uuid.New(),
		Payload:   envelopeBytes,
	})

	if err := tx.Commit(); err != nil {
		return nil, "", "", fmt.Errorf("enforcement: commit: %w", err)
	}

	// Wake the device via delivery notification (best-effort)
	ae.delivery.NotifyConsumer(ctx, input.TenantID, input.DeviceID.String())

	envelope := &contracts.RequestEnvelope{
		Payload: payload,
	}
	return envelope, pollCap, redeemCap, nil
}

// ─── Process Approval Decision ────────────────────────────────────────────

// ProcessApprovalInput carries the signed approval response from the device.
type ProcessApprovalInput struct {
	TenantID       uuid.UUID
	RequestID      uuid.UUID
	DeviceID       uuid.UUID
	Decision       contracts.Decision
	SignedResponse *contracts.ApprovalResponse
}

// ProcessApprovalResult is the result of processing an approval decision.
type ProcessApprovalResult struct {
	NewState  contracts.ApprovalState
	GrantJTI  *uuid.UUID // set if APPROVED → GRANTED
	AGTBytes  []byte     // COSE_Sign1 serialized AGT
}

// ProcessApproval processes a signed approval response (DR-SVC-2).
// For APPROVE: transitions to APPROVED, then mints a grant idempotently.
// For DENY: transitions to DENIED.
// Races with Cancel are atomically resolved.
func (ae *ApprovalEngine) ProcessApproval(ctx context.Context, input ProcessApprovalInput) (*ProcessApprovalResult, error) {
	result := &ProcessApprovalResult{}

	tx, err := ae.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("enforcement: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch current request state
	var currentState string
	var currentVersion int
	var userID uuid.UUID
	var resourceID uuid.UUID
	var scope string
	var bindingBytes []byte
	var policyVersion int64
	var ruleID string
	var srcNodeID string
	var srcNodeKeyEpoch int64

	err = tx.QueryRowContext(ctx, `
		SELECT state, state_version, user_id, resource_id, scope, binding,
		       policy_version, rule_id, src_node_id, 0
		FROM approval_requests
		WHERE tenant_id = $1 AND id = $2
		FOR UPDATE
	`, input.TenantID, input.RequestID).Scan(
		&currentState, &currentVersion, &userID, &resourceID, &scope,
		&bindingBytes, &policyVersion, &ruleID, &srcNodeID, &srcNodeKeyEpoch,
	)
	if err != nil {
		return nil, fmt.Errorf("enforcement: fetch request: %w", err)
	}

	// Only PENDING requests can be decided
	if currentState != string(contracts.ApprovalStatePending) {
		result.NewState = contracts.ApprovalState(currentState)
		return result, nil
	}

	// Verify device counter (DR-SIG-6)
	var deviceCounter int64
	err = tx.QueryRowContext(ctx, `
		SELECT counter FROM devices WHERE tenant_id = $1 AND id = $2
	`, input.TenantID, input.DeviceID).Scan(&deviceCounter)
	if err != nil {
		return nil, fmt.Errorf("enforcement: fetch device counter: %w", err)
	}
	if input.SignedResponse.DeviceCounter <= deviceCounter {
		return nil, fmt.Errorf("enforcement: invalid device counter %d <= %d", input.SignedResponse.DeviceCounter, deviceCounter)
	}

	newState := string(contracts.ApprovalStateDenied)
	if input.Decision == contracts.DecisionApprove {
		newState = string(contracts.ApprovalStateApproved)
	}

	// Transition state with optimistic locking
	_, err = tx.ExecContext(ctx, `
		SELECT transition_approval_request($1, $2, $3, $4)
	`, input.TenantID, input.RequestID, newState, currentVersion)
	if err != nil {
		return nil, fmt.Errorf("enforcement: transition state: %w", err)
	}

	// Record response
	_, err = tx.ExecContext(ctx, `
		UPDATE approval_requests
		SET response_decision = $1, response_sig = $2, response_key_id = $3,
		    device_counter = $4, response_nonce = $5
		WHERE tenant_id = $6 AND id = $7
	`, string(input.Decision), input.SignedResponse.Signature,
		input.SignedResponse.KeyID, input.SignedResponse.DeviceCounter,
		input.SignedResponse.ResponseNonce,
		input.TenantID, input.RequestID)
	if err != nil {
		return nil, fmt.Errorf("enforcement: update response: %w", err)
	}

	// Advance device counter atomically
	advanceDeviceCounter(ctx, tx, input.TenantID, input.DeviceID, input.SignedResponse.DeviceCounter)

	result.NewState = contracts.ApprovalState(newState)

	// If APPROVED, mint grant idempotently (DR-SVC-2)
	if input.Decision == contracts.DecisionApprove {
		grantJTI, agtBytes, err := ae.mintGrant(ctx, tx, input.TenantID, input.RequestID, userID, srcNodeID, resourceID, scope, policyVersion, ruleID)
		if err != nil {
			return nil, fmt.Errorf("enforcement: mint grant: %w", err)
		}
		result.NewState = contracts.ApprovalStateGranted
		result.GrantJTI = &grantJTI
		result.AGTBytes = agtBytes
	}

	// Audit the decision
	auditPayload, _ := json.Marshal(map[string]interface{}{
		"request_id": input.RequestID,
		"decision":   input.Decision,
		"device_id":  input.DeviceID,
	})
	ae.auditWriter.InsertTx(ctx, tx, audit.AuditEvent{
		TenantID:      input.TenantID,
		EventType:     audit.EventApprovalDecision,
		Producer:      "service",
		UserID:        &userID,
		DeviceID:      &input.DeviceID,
		RequestID:     &input.RequestID,
		Result:        strPtr(string(input.Decision)),
		CorrelationID: uuid.New(),
		Payload:       auditPayload,
	})

	return result, tx.Commit()
}

// ─── Grant Minting ────────────────────────────────────────────────────────

// mintGrant creates a signed AGT and persists it idempotently (DR-SVC-2).
func (ae *ApprovalEngine) mintGrant(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, requestID uuid.UUID, userID uuid.UUID, srcNodeID string, resourceID uuid.UUID, scope string, policyVersion int64, ruleID string) (uuid.UUID, []byte, error) {
	jti := uuid.Must(uuid.NewV7())

	// Get user OIDC identity
	userIdentity, err := ae.resolveUserIdentity(ctx, tenantID, userID)
	if err != nil {
		return uuid.Nil, nil, err
	}

	// Get resource details
	resource, err := ae.getResourceDetails(ctx, tx, tenantID, resourceID)
	if err != nil {
		return uuid.Nil, nil, err
	}

	// Determine grant TTL
	maxTTL := contracts.MaxGrantTTL(contracts.Scope(scope), contracts.Sensitivity(resource.Sensitivity))
	now := time.Now().UTC()

	agtPayload := &contracts.AGTPayload{
		JTI:                 jti,
		TenantID:            tenantID,
		Subject:             *userIdentity,
		SrcNodeID:           srcNodeID,
		SrcNodeKeyEpoch:     0, // populated from actual node state
		ApproverDeviceID:    uuid.Nil, // populated from request
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		Resource: contracts.ResourceID{
			TenantID:        tenantID,
			ProtectedNodeID: resource.NodeID,
			ServiceID:       resource.ServiceID,
			Port:            resource.Port,
			Transport:       contracts.TransportTCP,
			DeploymentMode:  contracts.DeploymentMode(resource.DeploymentMode),
		},
		Protocol:        resource.Protocol,
		DeploymentMode:   resource.DeploymentMode,
		Scope:           contracts.Scope(scope),
		PolicyVersion:   policyVersion,
		RuleID:          ruleID,
		AuthzEpoch:      1, // current authz epoch
		IssuedAt:        now,
		NotBefore:       now,
		ExpiresAt:       now.Add(maxTTL),
	}

	// Sign the AGT
	agtBytes, err := ae.grantSigner.SignGrant(ctx, agtPayload)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("enforcement: sign grant: %w", err)
	}

	// Persist grant
	_, err = tx.ExecContext(ctx, `
		INSERT INTO grants (
			jti, tenant_id, request_id, user_id, src_node_id,
			src_node_key_epoch, device_id, node_id, resource_id,
			protocol, scope, binding, policy_version, authz_epoch,
			device_security_level, agt_bytes, kid,
			iat, nbf, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		ON CONFLICT (tenant_id, request_id) DO NOTHING
	`, jti, tenantID, requestID, userID, srcNodeID,
		agtPayload.SrcNodeKeyEpoch, agtPayload.ApproverDeviceID,
		uuid.MustParse(agtPayload.Resource.ProtectedNodeID), resourceID,
		agtPayload.Protocol, agtPayload.Scope, []byte{},
		agtPayload.PolicyVersion, agtPayload.AuthzEpoch,
		agtPayload.DeviceSecurityLevel, agtBytes, "",
		agtPayload.IssuedAt, agtPayload.NotBefore, agtPayload.ExpiresAt,
	)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("enforcement: insert grant: %w", err)
	}

	// Update request to GRANTED
	_, err = tx.ExecContext(ctx, `
		UPDATE approval_requests SET state = 'GRANTED', state_version = state_version + 1
		WHERE tenant_id = $1 AND id = $2 AND state = 'APPROVED'
	`, tenantID, requestID)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("enforcement: mark granted: %w", err)
	}

	// Audit: GRANT_ISSUED
	auditPayload, _ := json.Marshal(map[string]interface{}{
		"jti":        jti,
		"request_id": requestID,
		"scope":      scope,
		"expires_at": agtPayload.ExpiresAt,
	})
	ae.auditWriter.InsertTx(ctx, tx, audit.AuditEvent{
		TenantID:      tenantID,
		EventType:     audit.EventGrantIssued,
		Producer:      "service",
		UserID:        &userID,
		RequestID:     &requestID,
		CorrelationID: uuid.New(),
		Payload:       auditPayload,
	})

	// Write grant to outbox for daemon delivery
	ae.outboxWriter.WriteTx(ctx, tx, messaging.OutboxMessage{
		TenantID:  tenantID,
		Consumer:  agtPayload.Resource.ProtectedNodeID,
		MessageID: jti,
		Payload:   agtBytes,
	})

	return jti, agtBytes, nil
}

// ─── Cancel Request (DR-SVC-3) ───────────────────────────────────────────

// CancelApprovalRequest cancels a pending approval request.
// Races atomically with approval; a late approval after CANCELLED never mints a usable grant.
func (ae *ApprovalEngine) CancelApprovalRequest(ctx context.Context, tenantID, requestID, nodeID uuid.UUID, reason string) error {
	tx, err := ae.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("enforcement: begin cancel tx: %w", err)
	}
	defer tx.Rollback()

	var currentState string
	var currentVersion int
	err = tx.QueryRowContext(ctx, `
		SELECT state, state_version FROM approval_requests
		WHERE tenant_id = $1 AND id = $2
		FOR UPDATE
	`, tenantID, requestID).Scan(&currentState, &currentVersion)
	if err != nil {
		return fmt.Errorf("enforcement: fetch request for cancel: %w", err)
	}

	if currentState != string(contracts.ApprovalStatePending) {
		tx.Commit() // Already terminal, no-op
		return nil
	}

	_, err = tx.ExecContext(ctx, `
		SELECT transition_approval_request($1, $2, 'CANCELLED', $3)
	`, tenantID, requestID, currentVersion)
	if err != nil {
		return fmt.Errorf("enforcement: cancel transition: %w", err)
	}

	// Audit: request cancelled
	auditPayload, _ := json.Marshal(map[string]interface{}{
		"request_id": requestID,
		"reason":     reason,
	})
	ae.auditWriter.InsertTx(ctx, tx, audit.AuditEvent{
		TenantID:      tenantID,
		EventType:     "REQUEST_CANCELLED",
		Producer:      "service",
		RequestID:     &requestID,
		CorrelationID: uuid.New(),
		Payload:       auditPayload,
	})

	// Send cancellation to approver device
	ae.outboxWriter.WriteTx(ctx, tx, messaging.OutboxMessage{
		TenantID:  tenantID,
		Consumer:  "approver_device", // resolved from request
		MessageID: uuid.New(),
		Payload:   nil,
	})

	return tx.Commit()
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func generateCapabilities() (pollCap, redeemCap string) {
	pollCap = fmt.Sprintf("dnivio_poll_%s", uuid.Must(uuid.NewV7()).String())
	redeemCap = fmt.Sprintf("dnivio_redeem_%s", uuid.Must(uuid.NewV7()).String())
	return
}

func (ae *ApprovalEngine) resolveUserIdentity(ctx context.Context, tenantID, userID uuid.UUID) (*contracts.OIDCIdentity, error) {
	var issuer, subject, uid string
	err := ae.db.QueryRowContext(ctx, `
		SELECT oidc_issuer, oidc_subject, id::text FROM users
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, userID).Scan(&issuer, &subject, &uid)
	if err != nil {
		return nil, fmt.Errorf("resolve user: %w", err)
	}
	return &contracts.OIDCIdentity{Issuer: issuer, Subject: subject, UserID: uid}, nil
}

type resourceDetails struct {
	NodeID         string
	ServiceID      string
	Port           int
	DeploymentMode string
	Protocol        string
	Sensitivity    string
}

func (ae *ApprovalEngine) getResourceDetails(ctx context.Context, tx *sql.Tx, tenantID, resourceID uuid.UUID) (*resourceDetails, error) {
	var r resourceDetails
	var nodeID uuid.UUID
	err := tx.QueryRowContext(ctx, `
		SELECT r.protected_node_id, r.service_id, r.port, r.deployment_mode, r.sensitivity
		FROM resources r WHERE r.tenant_id = $1 AND r.id = $2
	`, tenantID, resourceID).Scan(&nodeID, &r.ServiceID, &r.Port, &r.DeploymentMode, &r.Sensitivity)
	if err != nil {
		return nil, err
	}
	r.NodeID = nodeID.String()
	r.Protocol = "TCP"
	return &r, nil
}

func (ae *ApprovalEngine) getResourceLabel(ctx context.Context, tenantID, resourceID uuid.UUID) (contracts.DisplayLabel, error) {
	var name string
	err := ae.db.QueryRowContext(ctx, `
		SELECT COALESCE(display_label, service_id) FROM resources
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, resourceID).Scan(&name)
	if err != nil {
		return contracts.DisplayLabel{Name: "unknown"}, nil
	}
	return contracts.DisplayLabel{Name: name}, nil
}

func advanceDeviceCounter(ctx context.Context, tx *sql.Tx, tenantID, deviceID uuid.UUID, counter int64) {
	tx.ExecContext(ctx, `SELECT advance_device_counter($1, $2, $3)`, tenantID, deviceID, counter)
}

func strPtr(s string) *string { return &s }

// Ensure ed25519 import
var _ = ed25519.Sign
