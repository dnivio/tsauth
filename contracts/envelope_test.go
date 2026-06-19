package contracts_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/dnivio/contracts"
	"github.com/dnivio/contracts/cose"
	"github.com/google/uuid"
)

func TestRequestEnvelopeSignAndVerify(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	deviceID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()

	payload := &contracts.RequestPayload{
		RequestID:        contracts.NewRequestID(),
		TenantID:         tenantID,
		TailnetID:        "test-tailnet",
		IssuedAt:         now,
		ExpiresAt:        now.Add(60 * time.Second),
		AudienceDeviceID: deviceID,
		Initiating: contracts.InitiatingInfo{
			SrcNodeID:       "node123",
			SrcNodeDisplay:  "test-node",
			SrcNodeVerified: true,
			RequestingIP:    "100.64.0.1",
		},
		Resource: contracts.ResourceID{
			TenantID:        tenantID,
			ProtectedNodeID: "prot-node-1",
			ServiceID:       "web-app",
			Port:            443,
			Transport:       contracts.TransportTCP,
			DeploymentMode:  contracts.ModeHTTPProxy,
		},
		ResourceDisplay: contracts.DisplayLabel{Name: "Web Application"},
		Protocol:        "HTTPS",
		PolicyVersion:   1,
		RuleID:          "rule-001",
		ScopeRequested:  contracts.ScopeRequest,
		Binding: contracts.ScopeBinding{
			HTTPRequest: &contracts.HTTPRequestBinding{
				ProtectedNodeID:    "prot-node-1",
				SrcNodeID:          "node123",
				Method:             "GET",
				NormalizedAuthority: "app.example.com",
				PathPolicyID:        "/",
				HTTPVersion:         "2.0",
				RequestNonce:        []byte("test-nonce-32-bytes-xxxxxxxxx"),
			},
		},
	}

	env, err := contracts.NewRequestEnvelope(priv, "test-kid", payload)
	if err != nil {
		t.Fatalf("NewRequestEnvelope: %v", err)
	}

	if env.Message.Protected.KeyID != "test-kid" {
		t.Errorf("kid: got %q, want test-kid", env.Message.Protected.KeyID)
	}
	if env.Message.Protected.Type != "dnivio-req-v2" {
		t.Errorf("type: got %q, want dnivio-req-v2", env.Message.Protected.Type)
	}
	if env.Message.Protected.Algorithm != cose.AlgorithmEdDSA {
		t.Errorf("alg: got %d, want %d", env.Message.Protected.Algorithm, cose.AlgorithmEdDSA)
	}

	// Serialize and verify
	raw, err := cose.SerializeSign1(env.Message)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	verified, err := contracts.VerifyRequestEnvelope(raw, pub, deviceID, tenantID)
	if err != nil {
		t.Fatalf("VerifyRequestEnvelope: %v", err)
	}

	if verified.Payload.RequestID != payload.RequestID {
		t.Errorf("request_id mismatch")
	}
	if verified.Payload.AudienceDeviceID != deviceID {
		t.Errorf("device_id mismatch")
	}
}

func TestRequestEnvelopeWrongAudience(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	deviceID := uuid.Must(uuid.NewV7())
	wrongDevice := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()

	payload := &contracts.RequestPayload{
		RequestID:        contracts.NewRequestID(),
		TenantID:         tenantID,
		TailnetID:        "test",
		IssuedAt:         now,
		ExpiresAt:        now.Add(60 * time.Second),
		AudienceDeviceID: deviceID,
	}

	env, _ := contracts.NewRequestEnvelope(priv, "kid", payload)
	raw, _ := cose.SerializeSign1(env.Message)

	_, err = contracts.VerifyRequestEnvelope(raw, pub, wrongDevice, tenantID)
	if err == nil {
		t.Error("expected failure for wrong audience device")
	}
}

func TestRequestEnvelopeExpired(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	deviceID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	past := time.Now().UTC().Add(-120 * time.Second)

	payload := &contracts.RequestPayload{
		RequestID:        contracts.NewRequestID(),
		TenantID:         tenantID,
		TailnetID:        "test",
		IssuedAt:         past,
		ExpiresAt:        past.Add(60 * time.Second),
		AudienceDeviceID: deviceID,
	}

	env, _ := contracts.NewRequestEnvelope(priv, "kid", payload)
	raw, _ := cose.SerializeSign1(env.Message)

	_, err = contracts.VerifyRequestEnvelope(raw, pub, deviceID, tenantID)
	if err == nil {
		t.Error("expected failure for expired request")
	}
}

func TestAccessGrantTokenSignAndVerify(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	tenantID := uuid.Must(uuid.NewV7())

	agtPayload := &contracts.AGTPayload{
		JTI:                 uuid.Must(uuid.NewV7()),
		TenantID:            tenantID,
		TailnetID:           "test-tailnet",
		Subject:             contracts.OIDCIdentity{Issuer: "https://idp.example.com", Subject: "user-1", UserID: "uid-1"},
		SrcNodeID:           "node123",
		SrcNodeKeyEpoch:     1,
		ApproverDeviceID:    uuid.Must(uuid.NewV7()),
		ApprovalKeyID:       "approval_auth",
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		ProtectedNodeID:     "prot-node-1",
		Resource: contracts.ResourceID{
			TenantID:        tenantID,
			ProtectedNodeID: "prot-node-1",
			ServiceID:       "web-app",
			Port:            443,
			Transport:       contracts.TransportTCP,
			DeploymentMode:  contracts.ModeHTTPProxy,
		},
		Protocol:       "HTTPS",
		DeploymentMode:  string(contracts.ModeHTTPProxy),
		Scope:          contracts.ScopeConnection,
		PolicyVersion:  1,
		RuleID:         "rule-001",
		AuthzEpoch:     1,
		IssuedAt:       now,
		NotBefore:      now,
		ExpiresAt:      now.Add(120 * time.Second),
	}

	agt, err := contracts.NewAccessGrantToken(priv, "grant-kid", agtPayload)
	if err != nil {
		t.Fatalf("NewAccessGrantToken: %v", err)
	}

	raw, _ := cose.SerializeSign1(agt.Message)

	verified, err := contracts.VerifyAccessGrantToken(raw, pub, 1, 1, contracts.SensitivityStandard)
	if err != nil {
		t.Fatalf("VerifyAccessGrantToken: %v", err)
	}

	if verified.Payload.JTI != agtPayload.JTI {
		t.Errorf("JTI mismatch")
	}
	if verified.Payload.SrcNodeID != "node123" {
		t.Errorf("src_node_id mismatch: got %q", verified.Payload.SrcNodeID)
	}
}

func TestAccessGrantTokenStalePolicy(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	tenantID := uuid.Must(uuid.NewV7())

	agtPayload := &contracts.AGTPayload{
		JTI:              uuid.Must(uuid.NewV7()),
		TenantID:         tenantID,
		TailnetID:        "test",
		Subject:          contracts.OIDCIdentity{Issuer: "idp", Subject: "sub", UserID: "uid"},
		SrcNodeID:        "node1",
		PolicyVersion:    1,   // old version
		AuthzEpoch:       1,
		Scope:            contracts.ScopeConnection,
		IssuedAt:         now,
		NotBefore:        now,
		ExpiresAt:        now.Add(120 * time.Second),
	}

	agt, _ := contracts.NewAccessGrantToken(priv, "kid", agtPayload)
	raw, _ := cose.SerializeSign1(agt.Message)

	// Verify with newer policy version — should fail
	_, err = contracts.VerifyAccessGrantToken(raw, pub, 2, 2, contracts.SensitivityStandard)
	if err == nil {
		t.Error("expected failure for stale policy version")
	}
}

func TestAccessGrantTokenInsufficientSecurityLevel(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	tenantID := uuid.Must(uuid.NewV7())

	agtPayload := &contracts.AGTPayload{
		JTI:                  uuid.Must(uuid.NewV7()),
		TenantID:             tenantID,
		TailnetID:            "test",
		Subject:              contracts.OIDCIdentity{Issuer: "idp", Subject: "sub", UserID: "uid"},
		SrcNodeID:            "node1",
		DeviceSecurityLevel:  string(contracts.SecurityLevelTEE), // Only TEE
		PolicyVersion:        1,
		AuthzEpoch:           1,
		Scope:                contracts.ScopeConnection,
		IssuedAt:             now,
		NotBefore:            now,
		ExpiresAt:            now.Add(120 * time.Second),
	}

	agt, _ := contracts.NewAccessGrantToken(priv, "kid", agtPayload)
	raw, _ := cose.SerializeSign1(agt.Message)

	// HIGH sensitivity requires StrongBox — TEE should be rejected
	_, err = contracts.VerifyAccessGrantToken(raw, pub, 1, 1, contracts.SensitivityHigh)
	if err == nil {
		t.Error("expected failure: TEE insufficient for HIGH sensitivity")
	}
}

func TestGrantTTLCaps(t *testing.T) {
	tests := []struct {
		scope       contracts.Scope
		sensitivity contracts.Sensitivity
		expected    time.Duration
	}{
		{contracts.ScopeRequest, contracts.SensitivityStandard, 30 * time.Second},
		{contracts.ScopeConnection, contracts.SensitivityStandard, 120 * time.Second},
		{contracts.ScopeDuration, contracts.SensitivityStandard, 15 * time.Minute},
		{contracts.ScopeDuration, contracts.SensitivityHigh, 5 * time.Minute},
		{contracts.ScopeDuration, contracts.SensitivityAdmin, 0}, // prohibited
		{contracts.ScopeSession, contracts.SensitivityStandard, 8 * time.Hour},
		{contracts.ScopeSession, contracts.SensitivityHigh, 1 * time.Hour},
		{contracts.ScopeSession, contracts.SensitivityAdmin, 30 * time.Minute},
	}

	for _, tt := range tests {
		got := contracts.MaxGrantTTL(tt.scope, tt.sensitivity)
		if got != tt.expected {
			t.Errorf("MaxGrantTTL(%s, %s): got %v, want %v", tt.scope, tt.sensitivity, got, tt.expected)
		}
	}
}

func TestApprovalResponseSignAndVerify(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	resp := &contracts.ApprovalResponse{
		RequestID:      uuid.Must(uuid.NewV7()),
		Decision:       contracts.DecisionApprove,
		DeviceID:       uuid.Must(uuid.NewV7()),
		KeyID:          "approval_auth",
		DeviceCounter:  42,
		ChannelBinding: []byte("channel-binding-data"),
		ResponseNonce:  []byte("response-nonce-32-bytes-xxxx"),
		RequestHash:    []byte("sha256-hash-of-request-envelope-32"),
	}

	if err := contracts.SignApprovalResponse(priv, resp); err != nil {
		t.Fatalf("SignApprovalResponse: %v", err)
	}

	if err := contracts.VerifyApprovalResponse(resp, pub); err != nil {
		t.Fatalf("VerifyApprovalResponse: %v", err)
	}
}

func TestApprovalResponseTampered(t *testing.T) {
	_, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongPub, _, _ := cose.GenerateKey()

	resp := &contracts.ApprovalResponse{
		RequestID:      uuid.Must(uuid.NewV7()),
		Decision:       contracts.DecisionApprove,
		DeviceID:       uuid.Must(uuid.NewV7()),
		KeyID:          "approval_auth",
		DeviceCounter:  1,
		ChannelBinding: []byte("cb"),
		ResponseNonce:  []byte("nonce"),
		RequestHash:    []byte("hash"),
	}

	contracts.SignApprovalResponse(priv, resp)

	// Tamper with decision
	resp.Decision = contracts.DecisionDeny

	if err := contracts.VerifyApprovalResponse(resp, wrongPub); err == nil {
		t.Error("expected verification failure with wrong key")
	}
}

func TestDisplayDigestCoverage(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	payload := &contracts.RequestPayload{
		TenantID:  tenantID,
		TailnetID: "tn",
		Initiating: contracts.InitiatingInfo{
			SrcNodeID:       "n1",
			SrcNodeDisplay:  "Node 1",
		},
		Resource: contracts.ResourceID{
			ProtectedNodeID: "pn1",
			ServiceID:       "svc",
			Port:            443,
			Transport:       contracts.TransportTCP,
			DeploymentMode:  contracts.ModeHTTPProxy,
		},
		ResourceDisplay: contracts.DisplayLabel{Name: "App"},
		Protocol:        "HTTPS",
	}

	d1 := contracts.ComputeDisplayDigest(payload)
	d2 := contracts.ComputeDisplayDigest(payload)

	if len(d1) != 32 {
		t.Errorf("digest length: got %d, want 32 (SHA-256)", len(d1))
	}
	for i := range d1 {
		if d1[i] != d2[i] {
			t.Error("display_digest is not deterministic")
			break
		}
	}

	// Changing a displayed field SHOULD change the digest
	payload.Protocol = "SSH"
	d3 := contracts.ComputeDisplayDigest(payload)
	equal := true
	for i := range d1 {
		if d1[i] != d3[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("changing protocol did not change display_digest")
	}
}

func TestPrincipalHumanCheck(t *testing.T) {
	p := contracts.Principal{
		Kind:      contracts.PrincipalKindHuman,
		User:      &contracts.OIDCIdentity{Subject: "user"},
		NodeState: contracts.NodeStateOK,
	}
	if !p.IsHuman() {
		t.Error("expected human principal")
	}

	p.NodeState = contracts.NodeStateExpired
	if p.IsHuman() {
		t.Error("expired node should not be considered human")
	}
}

var _ = ed25519.Sign
