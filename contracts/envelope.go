// Package contracts/envelope defines the signed transaction envelopes for Dnivio:
// RequestEnvelope (§9.1), ApprovalResponse (§9.3), and AccessGrantToken (§9.3).
// Per ENGINEERING.md v2.1 §9 — all use COSE_Sign1 with deterministic CBOR.
package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/dnivio/contracts/cose"
	"github.com/google/uuid"
)

// ─── RequestEnvelope (§9.1, DR-SIG-1…3) ───────────────────────────────────

// RequestPayload is the canonical payload inside a signed approval request.
// Every security-relevant displayed field is inside this payload and covered by display_digest.
type RequestPayload struct {
	Ver               int          `json:"ver" cbor:"1,keyasint"`                              // version 2
	RequestID         uuid.UUID    `json:"request_id" cbor:"2,keyasint"`                        // UUIDv7
	TenantID          uuid.UUID    `json:"tenant_id" cbor:"3,keyasint"`
	TailnetID         string       `json:"tailnet_id" cbor:"4,keyasint"`
	IssuedAt          time.Time    `json:"issued_at" cbor:"5,keyasint"`
	ExpiresAt         time.Time    `json:"expires_at" cbor:"6,keyasint"`                        // default 60s TTL
	AudienceDeviceID  uuid.UUID    `json:"audience_device_id" cbor:"7,keyasint"`                // which approver this is for
	Initiating        InitiatingInfo `json:"initiating" cbor:"8,keyasint"`
	Resource          ResourceID   `json:"resource" cbor:"9,keyasint"`
	ResourceDisplay   DisplayLabel `json:"resource_display" cbor:"10,keyasint"`
	Protocol          string       `json:"protocol" cbor:"11,keyasint"`                         // HTTP, HTTPS, TCP, SSH
	SSHAccount        string       `json:"ssh_account,omitempty" cbor:"12,keyasint,omitempty"`  // account-aware modes
	PolicyVersion     int64        `json:"policy_version" cbor:"13,keyasint"`
	RuleID            string       `json:"rule_id" cbor:"14,keyasint"`
	ScopeRequested    Scope        `json:"scope_requested" cbor:"15,keyasint"`
	Binding           ScopeBinding `json:"binding" cbor:"16,keyasint"`                          // the concrete flow/session/request binding
	Challenge         []byte       `json:"challenge" cbor:"17,keyasint"`                        // single-use server nonce (32 bytes)
	DisplayDigest     []byte       `json:"display_digest" cbor:"18,keyasint"`                   // SHA-256 of display fields
}

// InitiatingInfo describes the source of an access attempt shown to the approver.
type InitiatingInfo struct {
	SrcNodeID        string `json:"src_node_id" cbor:"1,keyasint"`
	SrcNodeDisplay   string `json:"src_node_display" cbor:"2,keyasint"`
	SrcNodeVerified  bool   `json:"src_node_verified" cbor:"3,keyasint"`
	RequestingIP     string `json:"requesting_ip" cbor:"4,keyasint"`
	PostureVersion   string `json:"posture_version" cbor:"5,keyasint"`
}

// RequestEnvelope is the COSE_Sign1 wrapper around RequestPayload.
type RequestEnvelope struct {
	Message  *cose.Sign1Message
	Payload  *RequestPayload
}

// NewRequestEnvelope creates and signs a RequestEnvelope.
// signer is the service's request_sig Ed25519 private key.
func NewRequestEnvelope(signer ed25519.PrivateKey, kid string, payload *RequestPayload) (*RequestEnvelope, error) {
	payload.Ver = 2
	if payload.IssuedAt.IsZero() {
		payload.IssuedAt = time.Now().UTC()
	}
	if payload.ExpiresAt.IsZero() {
		payload.ExpiresAt = payload.IssuedAt.Add(60 * time.Second)
	}

	// Compute display_digest over the exact fields shown to the user
	payload.DisplayDigest = ComputeDisplayDigest(payload)

	payloadBytes, err := cose.EncodeCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal request payload: %w", err)
	}

	msg, err := cose.Sign1(signer, kid, "dnivio-req-v2", payloadBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: sign request: %w", err)
	}

	return &RequestEnvelope{Message: msg, Payload: payload}, nil
}

// VerifyRequestEnvelope verifies a COSE_Sign1 request envelope and returns the payload.
// Per DR-SIG-1: verifies signature, algorithm, kid, audience, tenant, canonical encoding.
func VerifyRequestEnvelope(rawEnvelope []byte, trustRoot ed25519.PublicKey, expectedDeviceID uuid.UUID, expectedTenant uuid.UUID) (*RequestEnvelope, error) {
	msg, err := cose.DeserializeSign1(rawEnvelope)
	if err != nil {
		return nil, fmt.Errorf("envelope: deserialize request: %w", err)
	}

	// Verify signature
	payloadBytes, headers, err := cose.Verify1(msg, trustRoot)
	if err != nil {
		return nil, fmt.Errorf("envelope: verify request signature: %w", err)
	}

	if headers.Type != "dnivio-req-v2" {
		return nil, fmt.Errorf("envelope: unexpected type %q", headers.Type)
	}

	// Decode payload
	var payload RequestPayload
	if err := cose.DecodeCanonical(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("envelope: decode request payload: %w", err)
	}

	// DR-SIG-1 checks
	if payload.AudienceDeviceID != expectedDeviceID {
		return nil, fmt.Errorf("envelope: request audience mismatch")
	}
	if payload.TenantID != expectedTenant {
		return nil, fmt.Errorf("envelope: request tenant mismatch")
	}
	if time.Now().UTC().After(payload.ExpiresAt.Add(5 * time.Second)) { // 5s skew bound
		return nil, fmt.Errorf("envelope: request expired")
	}
	if time.Now().UTC().Add(5 * time.Second).Before(payload.IssuedAt) {
		return nil, fmt.Errorf("envelope: request issued in future")
	}

	// Verify display_digest
	expectedDigest := ComputeDisplayDigest(&payload)
	if !hmacEqual(payload.DisplayDigest, expectedDigest) {
		return nil, fmt.Errorf("envelope: display digest mismatch")
	}

	return &RequestEnvelope{Message: msg, Payload: &payload}, nil
}

// ComputeDisplayDigest computes SHA-256 over the exact fields shown to the user.
// Per DR-SIG-2: covers tenant/tailnet, stable node id + display, ResourceID + display,
// port, protocol, SSH account, policy/rule id, scope, request/expiry times, binding.
func ComputeDisplayDigest(p *RequestPayload) []byte {
	h := sha256.New()

	// Include all displayed fields in deterministic order
	writeField := func(s string) { h.Write([]byte(s)) }
	writeField(p.TenantID.String())
	writeField(p.TailnetID)
	writeField(p.Initiating.SrcNodeID)
	writeField(p.Initiating.SrcNodeDisplay)
	writeField(p.Resource.ProtectedNodeID)
	writeField(p.Resource.ServiceID)
	writeField(fmt.Sprintf("%d", p.Resource.Port))
	writeField(string(p.Resource.Transport))
	writeField(string(p.Resource.DeploymentMode))
	writeField(p.ResourceDisplay.Name)
	writeField(p.Protocol)
	if p.SSHAccount != "" {
		writeField(p.SSHAccount)
	}
	writeField(fmt.Sprintf("%d", p.PolicyVersion))
	writeField(p.RuleID)
	writeField(string(p.ScopeRequested))
	writeField(fmt.Sprintf("%d", p.IssuedAt.Truncate(time.Second).Unix()))
	writeField(fmt.Sprintf("%d", p.ExpiresAt.Truncate(time.Second).Unix()))

	// Include binding
	bindingBytes, _ := cose.EncodeCanonical(p.Binding)
	h.Write(bindingBytes)

	return h.Sum(nil)
}

// ─── ApprovalResponse (§9.3, DR-SIG-5…6) ──────────────────────────────────

// ApprovalResponse is the signed decision from an approver device.
type ApprovalResponse struct {
	RequestID      uuid.UUID `json:"request_id" cbor:"1,keyasint"`
	Decision       Decision  `json:"decision" cbor:"2,keyasint"`        // APPROVE or DENY
	DeviceID       uuid.UUID `json:"device_id" cbor:"3,keyasint"`
	KeyID          string    `json:"key_id" cbor:"4,keyasint"`          // approval_auth for approve; device_auth for deny
	SignedAt       time.Time `json:"signed_at" cbor:"5,keyasint"`
	DeviceCounter  int64     `json:"device_counter" cbor:"6,keyasint"`  // monotonic anti-clone
	ChannelBinding []byte    `json:"channel_binding" cbor:"7,keyasint"`
	ResponseNonce  []byte    `json:"response_nonce" cbor:"8,keyasint"`
	RequestHash    []byte    `json:"request_hash" cbor:"9,keyasint"`    // SHA-256 of full RequestEnvelope
	Signature      []byte    `json:"signature" cbor:"10,keyasint"`      // Ed25519 signature over the message
}

// SignApprovalResponse signs an approval response.
// For APPROVE: uses approval_auth key; for DENY: uses device_auth key (DR-SIG-5).
func SignApprovalResponse(signer ed25519.PrivateKey, resp *ApprovalResponse) error {
	resp.SignedAt = time.Now().UTC()

	// Sign: hash(RequestEnvelope) || decision || device_id || key_id || signed_at || counter || channel_binding || response_nonce
	toSign := make([]byte, 0, sha256.Size+len(resp.Decision)+16+len(resp.KeyID)+8+8+len(resp.ChannelBinding)+len(resp.ResponseNonce)+32)
	toSign = append(toSign, resp.RequestHash...)
	toSign = append(toSign, []byte(resp.Decision)...)
	toSign = append(toSign, resp.DeviceID[:]...)
	toSign = append(toSign, []byte(resp.KeyID)...)
	signedAtBytes, _ := resp.SignedAt.MarshalBinary()
	toSign = append(toSign, signedAtBytes...)
	toSign = append(toSign, int64ToBytes(resp.DeviceCounter)...)
	toSign = append(toSign, resp.ChannelBinding...)
	toSign = append(toSign, resp.ResponseNonce...)

	resp.Signature = ed25519.Sign(signer, toSign)
	return nil
}

// VerifyApprovalResponse verifies an approval response signature.
func VerifyApprovalResponse(resp *ApprovalResponse, pubKey ed25519.PublicKey) error {
	toSign := make([]byte, 0, sha256.Size+len(resp.Decision)+16+len(resp.KeyID)+8+8+len(resp.ChannelBinding)+len(resp.ResponseNonce)+32)
	toSign = append(toSign, resp.RequestHash...)
	toSign = append(toSign, []byte(resp.Decision)...)
	toSign = append(toSign, resp.DeviceID[:]...)
	toSign = append(toSign, []byte(resp.KeyID)...)
	signedAtBytes, _ := resp.SignedAt.MarshalBinary()
	toSign = append(toSign, signedAtBytes...)
	toSign = append(toSign, int64ToBytes(resp.DeviceCounter)...)
	toSign = append(toSign, resp.ChannelBinding...)
	toSign = append(toSign, resp.ResponseNonce...)

	if !ed25519.Verify(pubKey, toSign, resp.Signature) {
		return fmt.Errorf("envelope: approval response signature verification failed")
	}
	return nil
}

// ─── Access Grant Token (§9.3, DR-GRANT-1…3) ──────────────────────────────

// AccessGrantToken is the COSE_Sign1 authorization granting access to a protected resource.
// Carries the full binding set per DR-GRANT-1.
type AGTPayload struct {
	Ver               int          `json:"ver" cbor:"1,keyasint"`              // version 2
	JTI               uuid.UUID    `json:"jti" cbor:"2,keyasint"`              // JWT ID / unique grant identifier
	TenantID          uuid.UUID    `json:"tenant_id" cbor:"3,keyasint"`
	TailnetID         string       `json:"tailnet_id" cbor:"4,keyasint"`
	Subject           OIDCIdentity `json:"sub" cbor:"5,keyasint"`
	SrcNodeID         string       `json:"src_node_id" cbor:"6,keyasint"`      // INITIATING node (resolves C-04)
	SrcNodeKeyEpoch   int64        `json:"src_node_key_epoch" cbor:"7,keyasint"`
	ApproverDeviceID  uuid.UUID    `json:"approver_device_id" cbor:"8,keyasint"`
	ApprovalKeyID     string       `json:"approval_key_id" cbor:"9,keyasint"`
	DeviceSecurityLevel string     `json:"device_security_level" cbor:"10,keyasint"` // STRONGBOX or TEE
	ProtectedNodeID   string       `json:"nod" cbor:"11,keyasint"`
	Resource          ResourceID   `json:"resource" cbor:"12,keyasint"`
	Protocol          string       `json:"protocol" cbor:"13,keyasint"`
	DeploymentMode    string       `json:"deployment_mode" cbor:"14,keyasint"`
	Scope             Scope        `json:"scope" cbor:"15,keyasint"`
	Binding           ScopeBinding `json:"binding" cbor:"16,keyasint"`         // scope-specific
	PolicyVersion     int64        `json:"policy_version" cbor:"17,keyasint"`
	RuleID            string       `json:"rule_id" cbor:"18,keyasint"`
	AuthzEpoch        int64        `json:"authz_epoch" cbor:"19,keyasint"`     // staleness binding (resolves C-10)
	IssuedAt          time.Time    `json:"iat" cbor:"20,keyasint"`
	NotBefore         time.Time    `json:"nbf" cbor:"21,keyasint"`
	ExpiresAt         time.Time    `json:"exp" cbor:"22,keyasint"`
}

// AccessGrantToken is the COSE_Sign1 wrapper around AGTPayload.
type AccessGrantToken struct {
	Message *cose.Sign1Message
	Payload *AGTPayload
}

// NewAccessGrantToken creates and signs an AGT with the grant_sig key.
func NewAccessGrantToken(signer ed25519.PrivateKey, kid string, payload *AGTPayload) (*AccessGrantToken, error) {
	payload.Ver = 2
	now := time.Now().UTC()
	if payload.IssuedAt.IsZero() {
		payload.IssuedAt = now
	}
	if payload.NotBefore.IsZero() {
		payload.NotBefore = now
	}

	payloadBytes, err := cose.EncodeCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal agt payload: %w", err)
	}

	msg, err := cose.Sign1(signer, kid, "dnivio-agt-v2", payloadBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: sign agt: %w", err)
	}

	return &AccessGrantToken{Message: msg, Payload: payload}, nil
}

// VerifyAccessGrantToken verifies a COSE_Sign1 AGT and performs all acceptance checks per DR-GRANT-2.
func VerifyAccessGrantToken(rawAGT []byte, trustRoot ed25519.PublicKey, currentAuthzEpoch, currentPolicyVersion int64, currentSensitivity Sensitivity) (*AccessGrantToken, error) {
	msg, err := cose.DeserializeSign1(rawAGT)
	if err != nil {
		return nil, fmt.Errorf("envelope: deserialize agt: %w", err)
	}

	payloadBytes, headers, err := cose.Verify1(msg, trustRoot)
	if err != nil {
		return nil, fmt.Errorf("envelope: verify agt signature: %w", err)
	}

	if headers.Type != "dnivio-agt-v2" {
		return nil, fmt.Errorf("envelope: unexpected agt type %q", headers.Type)
	}

	var payload AGTPayload
	if err := cose.DecodeCanonical(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("envelope: decode agt payload: %w", err)
	}

	// DR-GRANT-2 acceptance checks
	now := time.Now().UTC()
	if now.Before(payload.NotBefore) {
		return nil, fmt.Errorf("envelope: agt not yet valid (nbf)")
	}
	if now.After(payload.ExpiresAt) {
		return nil, fmt.Errorf("envelope: agt expired")
	}

	// Policy staleness check (resolves C-10)
	if payload.PolicyVersion < currentPolicyVersion {
		return nil, fmt.Errorf("envelope: agt policy version %d < current %d", payload.PolicyVersion, currentPolicyVersion)
	}
	if payload.AuthzEpoch != currentAuthzEpoch {
		return nil, fmt.Errorf("envelope: agt authz epoch %d != current %d", payload.AuthzEpoch, currentAuthzEpoch)
	}

	// Device security level check
	if currentSensitivity == SensitivityHigh || currentSensitivity == SensitivityAdmin {
		if payload.DeviceSecurityLevel != string(SecurityLevelStrongBox) {
			return nil, fmt.Errorf("envelope: device security level %s insufficient for sensitivity %s", payload.DeviceSecurityLevel, currentSensitivity)
		}
	}

	return &AccessGrantToken{Message: msg, Payload: &payload}, nil
}

// ─── Grant TTL Caps (§9.3, DR-GRANT-3) ────────────────────────────────────

// MaxGrantTTL returns the maximum grant lifetime for a given scope and sensitivity.
// These are caps; policies may shorten but never increase.
func MaxGrantTTL(scope Scope, sensitivity Sensitivity) time.Duration {
	switch scope {
	case ScopeRequest:
		return 30 * time.Second
	case ScopeConnection:
		return 120 * time.Second
	case ScopeDuration:
		switch sensitivity {
		case SensitivityStandard:
			return 15 * time.Minute
		case SensitivityHigh:
			return 5 * time.Minute
		default: // ADMIN
			return 0 // DURATION prohibited for ADMIN
		}
	case ScopeSession:
		switch sensitivity {
		case SensitivityStandard:
			return 8 * time.Hour
		case SensitivityHigh:
			return 1 * time.Hour
		case SensitivityAdmin:
			return 30 * time.Minute
		}
	}
	return 0
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func hmacEqual(a, b []byte) bool {
	return len(a) == len(b) && subtleXORBytes(a, b) == 0
}

func subtleXORBytes(a, b []byte) byte {
	var diff byte
	for i := 0; i < len(a) && i < len(b); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff
}

func int64ToBytes(i int64) []byte {
	b := make([]byte, 8)
	b[0] = byte(i >> 56)
	b[1] = byte(i >> 48)
	b[2] = byte(i >> 40)
	b[3] = byte(i >> 32)
	b[4] = byte(i >> 24)
	b[5] = byte(i >> 16)
	b[6] = byte(i >> 8)
	b[7] = byte(i)
	return b
}
