// Package contracts defines the frozen vocabulary types for the Dnivio authorization plane.
// These types implement §3 (Cross-cutting identity & resource model) of ENGINEERING.md v2.1.
package contracts

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/google/uuid"
)

// ─── §3.1 Tenancy ───────────────────────────────────────────────────────────

// TenantID is a UUIDv7 identifier for a tenant.
type TenantID = uuid.UUID

// ─── §3.2 Initiating Principal (DR-ID-1…6) ──────────────────────────────────

// PrincipalKind classifies the source of an access attempt.
type PrincipalKind string

const (
	PrincipalKindHuman        PrincipalKind = "HUMAN"
	PrincipalKindTagged       PrincipalKind = "TAGGED"
	PrincipalKindService      PrincipalKind = "SERVICE"
	PrincipalKindSubnetRouter PrincipalKind = "SUBNET_ROUTER"
	PrincipalKindAppConnector PrincipalKind = "APP_CONNECTOR"
	PrincipalKindUnknown      PrincipalKind = "UNKNOWN"
)

// NodeState represents the known state of a Tailscale node.
type NodeState string

const (
	NodeStateOK         NodeState = "OK"
	NodeStateExpired    NodeState = "EXPIRED"
	NodeStateDeleted    NodeState = "DELETED"
	NodeStateKeyChanged NodeState = "KEY_CHANGED"
)

// OIDCIdentity is the (issuer, subject, user_id) tuple identifying a human user.
type OIDCIdentity struct {
	Issuer  string `json:"oidc_issuer" cbor:"1,keyasint"`
	Subject string `json:"oidc_subject" cbor:"2,keyasint"`
	UserID  string `json:"user_id" cbor:"3,keyasint"`
}

// Principal is the typed, resolved identity of an access attempt source (§3.2).
// DR-ID-1: derived from stable node id + tenant, never IP alone.
type Principal struct {
	TenantID       TenantID      `json:"tenant_id" cbor:"1,keyasint"`
	TailnetID      string        `json:"tailnet_id" cbor:"2,keyasint"`
	SrcNodeID      string        `json:"src_node_id" cbor:"3,keyasint"` // Tailscale STABLE node id
	SrcNodeKeyEpoch int64        `json:"src_node_key_epoch" cbor:"4,keyasint"`
	Kind           PrincipalKind `json:"kind" cbor:"5,keyasint"`
	User           *OIDCIdentity `json:"user,omitempty" cbor:"6,keyasint,omitempty"`
	NodeState      NodeState     `json:"node_state" cbor:"7,keyasint"`
	PostureVersion string        `json:"posture_version" cbor:"8,keyasint"` // snapshot id or "NONE"
}

// IsHuman returns true if a unique, non-expired human principal is established.
func (p Principal) IsHuman() bool {
	return p.Kind == PrincipalKindHuman &&
		p.User != nil &&
		p.User.Subject != "" &&
		p.NodeState == NodeStateOK
}

// ─── §3.3 Protected Resource Identity (DR-RES-1…3) ──────────────────────────

// Transport is the IP transport protocol for a protected resource.
type Transport string

const (
	TransportTCP Transport = "TCP"
)

// DeploymentMode is the enforcement mode for a protected resource (§7.4).
type DeploymentMode string

const (
	ModeHTTPProxy DeploymentMode = "HTTP_PROXY"
	ModeOpaqueTCP DeploymentMode = "OPAQUE_TCP"
	ModeTSSSH     DeploymentMode = "TS_SSH"
	ModeOpenSSH   DeploymentMode = "OPENSSH"
)

// ResourceID is the canonical typed identifier for a protected resource.
// DR-RES-1: bindings, policy, grants, and audit MUST reference this, never a display string.
type ResourceID struct {
	TenantID        TenantID       `json:"tenant_id" cbor:"1,keyasint"`
	ProtectedNodeID string         `json:"protected_node_id" cbor:"2,keyasint"`
	ServiceID       string         `json:"service_id" cbor:"3,keyasint"`
	Port            int            `json:"port" cbor:"4,keyasint"`
	Transport       Transport      `json:"transport" cbor:"5,keyasint"`
	DeploymentMode  DeploymentMode `json:"deployment_mode" cbor:"6,keyasint"`
}

// DisplayLabel holds untrusted human-readable display information.
// It MUST NOT be used in bindings, policy, or authorization decisions (DR-RES-1).
type DisplayLabel struct {
	Name       string `json:"name" cbor:"1,keyasint"`
	SourceHint string `json:"source_hint" cbor:"2,keyasint"`
}

// ─── §3.4 Key Identities ────────────────────────────────────────────────────

// KeyPurpose identifies the role of a cryptographic key.
type KeyPurpose string

const (
	KeyPurposeDeviceAuth    KeyPurpose = "device_auth"
	KeyPurposeApprovalAuth  KeyPurpose = "approval_auth"
	KeyPurposeRequestSig    KeyPurpose = "request_sig"
	KeyPurposeGrantSig      KeyPurpose = "grant_sig"
	KeyPurposePolicySig     KeyPurpose = "policy_sig"
	KeyPurposeAuditCheckpoint KeyPurpose = "audit_checkpoint_sig"
)

// KeyIdentity pairs a key identifier with its public key and purpose.
type KeyIdentity struct {
	Kid     string             `json:"kid" cbor:"1,keyasint"`
	Purpose KeyPurpose         `json:"purpose" cbor:"2,keyasint"`
	PubKey  ed25519.PublicKey  `json:"pub_key" cbor:"3,keyasint"`
}

// ─── Scope & Binding Types (§9.2) ───────────────────────────────────────────

// Scope is the granularity of an access grant.
type Scope string

const (
	ScopeRequest    Scope = "REQUEST"
	ScopeConnection Scope = "CONNECTION"
	ScopeDuration   Scope = "DURATION"
	ScopeSession    Scope = "SESSION"
)

// ScopeBinding is a mode/scope-specific binding, never a transport 5-tuple (DR-SIG-4).
type ScopeBinding struct {
	// HTTP_REQUEST binding (HTTP_PROXY + REQUEST scope)
	HTTPRequest *HTTPRequestBinding `json:"http_request,omitempty" cbor:"1,keyasint,omitempty"`
	// CONNECTION binding (OPAQUE_TCP/HTTP CONNECTION scope)
	Connection *ConnectionBinding `json:"connection,omitempty" cbor:"2,keyasint,omitempty"`
	// SESSION binding (TS_SSH/HTTP SESSION scope)
	Session *SessionBinding `json:"session,omitempty" cbor:"3,keyasint,omitempty"`
}

// HTTPRequestBinding binds a REQUEST scope grant to a specific HTTP request.
type HTTPRequestBinding struct {
	ProtectedNodeID  string `json:"protected_node_id" cbor:"1,keyasint"`
	SrcNodeID        string `json:"src_node_id" cbor:"2,keyasint"`
	Method           string `json:"method" cbor:"3,keyasint"`
	NormalizedAuthority string `json:"normalized_authority" cbor:"4,keyasint"`
	PathPolicyID     string `json:"path_policy_id" cbor:"5,keyasint"`
	HTTPVersion      string `json:"http_version" cbor:"6,keyasint"`
	RequestNonce     []byte `json:"request_nonce" cbor:"7,keyasint"` // server-generated
}

// ConnectionBinding binds a CONNECTION scope grant to a proxy-owned connection.
type ConnectionBinding struct {
	ConnectionID []byte `json:"connection_id" cbor:"1,keyasint"` // cryptographically random
}

// SessionBinding binds a SESSION scope grant to a live session.
type SessionBinding struct {
	SessionID []byte `json:"session_id" cbor:"1,keyasint"` // cryptographically random
}

// ─── Decision Lattice (§12.1, DR-POL-1/2) ───────────────────────────────────

// EnforcementDecision is the result of policy evaluation.
type EnforcementDecision string

const (
	DecisionNotProtected        EnforcementDecision = "NOT_PROTECTED"
	DecisionAllowWithoutStepUp  EnforcementDecision = "ALLOW_WITHOUT_STEP_UP"
	DecisionRequireStepUp       EnforcementDecision = "REQUIRE_STEP_UP"
	DecisionEnforceDeny         EnforcementDecision = "DENY"
)

// ─── Sensitivity Levels (§8.3, DR-KEY-6) ──────────────────────────────────

// SecurityLevel is the hardware security level of an approver device.
type SecurityLevel string

const (
	SecurityLevelStrongBox SecurityLevel = "STRONGBOX"
	SecurityLevelTEE       SecurityLevel = "TEE"
)

// Sensitivity is the classification of a protected resource.
type Sensitivity string

const (
	SensitivityStandard Sensitivity = "STANDARD"
	SensitivityHigh     Sensitivity = "HIGH"
	SensitivityAdmin    Sensitivity = "ADMIN"
)

// ─── Approval States (§11.3) ────────────────────────────────────────────────

// ApprovalState represents the lifecycle of an approval request.
type ApprovalState string

const (
	ApprovalStatePending   ApprovalState = "PENDING"
	ApprovalStateApproved  ApprovalState = "APPROVED"
	ApprovalStateGranted   ApprovalState = "GRANTED"
	ApprovalStateDenied    ApprovalState = "DENIED"
	ApprovalStateExpired   ApprovalState = "EXPIRED"
	ApprovalStateCancelled ApprovalState = "CANCELLED"
)

// IsTerminal returns true if the state is a terminal state.
func (s ApprovalState) IsTerminal() bool {
	switch s {
	case ApprovalStateDenied, ApprovalStateExpired, ApprovalStateCancelled:
		return true
	default:
		return false
	}
}

// ─── Decision type ──────────────────────────────────────────────────────────

// Decision represents an approve/deny decision from an approver device.
type Decision string

const (
	DecisionApprove Decision = "APPROVE"
	DecisionDeny    Decision = "DENY"
)

// ─── Time helpers ───────────────────────────────────────────────────────────

// NewRequestID generates a new UUIDv7 request identifier.
func NewRequestID() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}

// NewNonce generates a cryptographically random nonce of the given size.
func NewNonce(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
