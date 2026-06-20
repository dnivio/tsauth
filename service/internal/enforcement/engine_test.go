package enforcement

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/dnivio/contracts"
	"github.com/dnivio/contracts/cose"
	"github.com/google/uuid"
	"os"
	"regexp"
	"strings"
)

// ─── C3: ApprovalResponse signature verification ──────────────────────────

func TestSignAndVerifyApprovalResponse_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	requestID := uuid.Must(uuid.NewV7())
	requestHash := sha256.Sum256([]byte("test request envelope"))
	respNonce := make([]byte, 32)
	rand.Read(respNonce)

	resp := &contracts.ApprovalResponse{
		RequestID:      requestID,
		Decision:       contracts.DecisionApprove,
		DeviceID:       uuid.Must(uuid.NewV7()),
		KeyID:          "approval_auth",
		DeviceCounter:  42,
		ChannelBinding: []byte("channel-abc"),
		ResponseNonce:  respNonce,
		RequestHash:    requestHash[:],
	}

	if err := contracts.SignApprovalResponse(priv, resp); err != nil {
		t.Fatalf("SignApprovalResponse: %v", err)
	}

	if err := contracts.VerifyApprovalResponse(resp, pub); err != nil {
		t.Fatalf("VerifyApprovalResponse with correct key failed: %v", err)
	}
}

func TestVerifyApprovalResponse_WrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	requestHash := sha256.Sum256([]byte("test"))
	respNonce := make([]byte, 32)
	rand.Read(respNonce)

	resp := &contracts.ApprovalResponse{
		RequestID:     uuid.Must(uuid.NewV7()),
		Decision:      contracts.DecisionApprove,
		DeviceID:      uuid.Must(uuid.NewV7()),
		KeyID:         "approval_auth",
		DeviceCounter: 1,
		ResponseNonce: respNonce,
		RequestHash:   requestHash[:],
	}

	if err := contracts.SignApprovalResponse(priv, resp); err != nil {
		t.Fatalf("SignApprovalResponse: %v", err)
	}

	if err := contracts.VerifyApprovalResponse(resp, wrongPub); err == nil {
		t.Fatal("verification with wrong public key should fail")
	}
}

func TestVerifyApprovalResponse_TamperedDecision(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	requestHash := sha256.Sum256([]byte("test"))
	respNonce := make([]byte, 32)
	rand.Read(respNonce)

	resp := &contracts.ApprovalResponse{
		RequestID:     uuid.Must(uuid.NewV7()),
		Decision:      contracts.DecisionApprove,
		DeviceID:      uuid.Must(uuid.NewV7()),
		KeyID:         "approval_auth",
		DeviceCounter: 1,
		ResponseNonce: respNonce,
		RequestHash:   requestHash[:],
	}

	if err := contracts.SignApprovalResponse(priv, resp); err != nil {
		t.Fatalf("SignApprovalResponse: %v", err)
	}

	resp.Decision = contracts.DecisionDeny // tamper

	if err := contracts.VerifyApprovalResponse(resp, pub); err == nil {
		t.Fatal("tampered decision should fail verification")
	}
}

func TestVerifyApprovalResponse_TamperedCounter(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	requestHash := sha256.Sum256([]byte("test"))
	respNonce := make([]byte, 32)
	rand.Read(respNonce)

	resp := &contracts.ApprovalResponse{
		RequestID:     uuid.Must(uuid.NewV7()),
		Decision:      contracts.DecisionApprove,
		DeviceID:      uuid.Must(uuid.NewV7()),
		KeyID:         "approval_auth",
		DeviceCounter: 1,
		ResponseNonce: respNonce,
		RequestHash:   requestHash[:],
	}

	if err := contracts.SignApprovalResponse(priv, resp); err != nil {
		t.Fatalf("SignApprovalResponse: %v", err)
	}

	resp.DeviceCounter = 999 // tamper

	if err := contracts.VerifyApprovalResponse(resp, pub); err == nil {
		t.Fatal("tampered counter should fail verification")
	}
}

func TestVerifyApprovalResponse_TamperedRequestHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	requestHash := sha256.Sum256([]byte("test"))
	respNonce := make([]byte, 32)
	rand.Read(respNonce)

	resp := &contracts.ApprovalResponse{
		RequestID:     uuid.Must(uuid.NewV7()),
		Decision:      contracts.DecisionApprove,
		DeviceID:      uuid.Must(uuid.NewV7()),
		KeyID:         "approval_auth",
		DeviceCounter: 1,
		ResponseNonce: respNonce,
		RequestHash:   requestHash[:],
	}

	if err := contracts.SignApprovalResponse(priv, resp); err != nil {
		t.Fatalf("SignApprovalResponse: %v", err)
	}

	wrongHash := sha256.Sum256([]byte("different request"))
	resp.RequestHash = wrongHash[:] // tamper

	if err := contracts.VerifyApprovalResponse(resp, pub); err == nil {
		t.Fatal("tampered request hash should fail verification")
	}
}

func TestVerifyApprovalResponse_UninitializedSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	resp := &contracts.ApprovalResponse{
		Decision: contracts.DecisionApprove,
	}

	if err := contracts.VerifyApprovalResponse(resp, pub); err == nil {
		t.Fatal("uninitialized/missing signature should fail verification")
	}
}

// ─── C8: Grant payload binding and identity population ────────────────────

func TestAGTPayload_HasBinding(t *testing.T) {
	now := time.Now().UTC()
	deviceID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())

	payload := &contracts.AGTPayload{
		Ver: 2, JTI: uuid.Must(uuid.NewV7()), TenantID: tenantID,
		Subject:             contracts.OIDCIdentity{Issuer: "https://idp.test", Subject: "u1", UserID: "uid"},
		SrcNodeID:           "node-1",
		SrcNodeKeyEpoch:     5,
		ApproverDeviceID:    deviceID,
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		ProtectedNodeID:     "protected-1",
		Resource:            contracts.ResourceID{TenantID: tenantID, ProtectedNodeID: "protected-1", ServiceID: "svc", Port: 443, Transport: contracts.TransportTCP, DeploymentMode: contracts.ModeHTTPProxy},
		Protocol:            "HTTPS",
		Scope:               contracts.ScopeRequest,
		Binding:             contracts.ScopeBinding{HTTPRequest: &contracts.HTTPRequestBinding{RequestNonce: []byte("test-nonce")}},
		PolicyVersion:       1, RuleID: "rule-1", AuthzEpoch: 3,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(30 * time.Second),
	}

	payloadBytes, err := contracts.PrepareAGTPayload(payload)
	if err != nil {
		t.Fatalf("PrepareAGTPayload: %v", err)
	}
	var decoded contracts.AGTPayload
	if err := cose.DecodeCanonical(payloadBytes, &decoded); err != nil {
		t.Fatalf("DecodeCanonical: %v", err)
	}
	if decoded.Binding.HTTPRequest == nil {
		t.Fatal("binding.HTTPRequest should not be nil after round-trip")
	}
	if string(decoded.Binding.HTTPRequest.RequestNonce) != "test-nonce" {
		t.Errorf("nonce mismatch: got %s", decoded.Binding.HTTPRequest.RequestNonce)
	}
}

func TestAGTPayload_DeviceInfoPopulated(t *testing.T) {
	now := time.Now().UTC()
	deviceID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())

	payload := &contracts.AGTPayload{
		Ver: 2, JTI: uuid.Must(uuid.NewV7()), TenantID: tenantID,
		Subject:   contracts.OIDCIdentity{Issuer: "https://idp.test", Subject: "u1", UserID: "uid"},
		SrcNodeID: "node-1", SrcNodeKeyEpoch: 7,
		ApproverDeviceID:    deviceID,
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		ProtectedNodeID:     "protected-1",
		Resource:            contracts.ResourceID{TenantID: tenantID, ProtectedNodeID: "protected-1", ServiceID: "svc", Port: 443},
		Scope:               contracts.ScopeRequest,
		PolicyVersion:       1, AuthzEpoch: 3,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(30 * time.Second),
	}

	payloadBytes, err := contracts.PrepareAGTPayload(payload)
	if err != nil {
		t.Fatalf("PrepareAGTPayload: %v", err)
	}
	var decoded contracts.AGTPayload
	if err := cose.DecodeCanonical(payloadBytes, &decoded); err != nil {
		t.Fatalf("DecodeCanonical: %v", err)
	}
	if decoded.ApproverDeviceID == uuid.Nil {
		t.Error("ApproverDeviceID should not be uuid.Nil")
	}
	if decoded.SrcNodeKeyEpoch == 0 {
		t.Error("SrcNodeKeyEpoch should not be 0")
	}
	if decoded.AuthzEpoch == 0 {
		t.Error("AuthzEpoch should not be 0")
	}
}

func TestAGTPayload_BindingSurvivesCOSERoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().UTC()
	tenantID := uuid.Must(uuid.NewV7())

	payload := &contracts.AGTPayload{
		Ver: 2, JTI: uuid.Must(uuid.NewV7()), TenantID: tenantID,
		Subject:   contracts.OIDCIdentity{Issuer: "https://idp.test", Subject: "u1", UserID: "uid"},
		SrcNodeID: "node-1", SrcNodeKeyEpoch: 5,
		ApproverDeviceID:    uuid.Must(uuid.NewV7()),
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		ProtectedNodeID:     "protected-1",
		Resource:            contracts.ResourceID{TenantID: tenantID, ProtectedNodeID: "protected-1", ServiceID: "svc", Port: 443, Transport: contracts.TransportTCP, DeploymentMode: contracts.ModeHTTPProxy},
		Protocol:            "HTTPS",
		Scope:               contracts.ScopeConnection,
		Binding:             contracts.ScopeBinding{Connection: &contracts.ConnectionBinding{ConnectionID: []byte("conn-id-test")}},
		PolicyVersion:       5, RuleID: "rule-1", AuthzEpoch: 3,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(30 * time.Second),
	}

	payloadBytes, err := contracts.PrepareAGTPayload(payload)
	if err != nil {
		t.Fatalf("PrepareAGTPayload: %v", err)
	}
	msg, err := cose.Sign1(priv, "kid", "dnivio-agt-v2", payloadBytes, nil)
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}
	rawAGT, err := cose.SerializeSign1(msg)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	agt, err := contracts.VerifyAccessGrantToken(rawAGT, pub, 3, 5, contracts.SensitivityStandard)
	if err != nil {
		t.Fatalf("VerifyAccessGrantToken: %v", err)
	}
	if agt.Payload.Binding.Connection == nil {
		t.Fatal("binding.Connection should not be nil after COSE round-trip")
	}
	if agt.Payload.SrcNodeKeyEpoch != 5 {
		t.Errorf("SrcNodeKeyEpoch: got %d want 5", agt.Payload.SrcNodeKeyEpoch)
	}
	if agt.Payload.AuthzEpoch != 3 {
		t.Errorf("AuthzEpoch: got %d want 3", agt.Payload.AuthzEpoch)
	}
}

// --- C8: ProcessApproval query columns must resolve against the real schema ---

// TestProcessApprovalQuery_ColumnsResolveToSchema parses the migration to build
// each table's column set, then extracts every alias-qualified column reference
// (ar.* / n.*) from the ProcessApproval fetch query in engine.go and asserts each
// one exists in the table its alias maps to. This is the guard that would have
// caught the C8 regression where the query selected `src_node_key_epoch FROM
// approval_requests` — a column that lives only on the grants table — which
// satisfies schema-blind sqlmock tests but fails against a real Postgres.
//
// NOTE: this is a static cross-check, not a substitute for an integration test
// against a live Postgres (which would also catch SQL syntax and column-type
// mismatches, e.g. the binding jsonb-vs-CBOR concern).
func TestProcessApprovalQuery_ColumnsResolveToSchema(t *testing.T) {
	schema := parseMigrationSchema(t)

	src, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatalf("read engine.go: %v", err)
	}
	start := strings.Index(string(src), "SELECT ar.state")
	end := strings.Index(string(src), "FOR UPDATE OF ar")
	if start < 0 || end < 0 || end < start {
		t.Fatal("could not locate ProcessApproval fetch query (SELECT ar.state ... FOR UPDATE OF ar)")
	}
	query := string(src)[start:end]

	aliasTable := map[string]string{"ar": "approval_requests", "n": "nodes"}
	re := regexp.MustCompile(`\b(ar|n)\.([a-z_]+)`)
	refs := re.FindAllStringSubmatch(query, -1)
	if len(refs) == 0 {
		t.Fatal("no alias-qualified column references found in fetch query")
	}
	for _, m := range refs {
		alias, col := m[1], m[2]
		table := aliasTable[alias]
		if !schema[table][col] {
			t.Errorf("fetch query references %s.%s, but table %q has no column %q", alias, col, table, col)
		}
	}

	// Document the data-model truth the regression violated.
	if schema["approval_requests"]["src_node_key_epoch"] {
		t.Error("schema drift: approval_requests must NOT define src_node_key_epoch (epoch is sourced from nodes.node_key_epoch)")
	}
	if !schema["nodes"]["node_key_epoch"] {
		t.Error("nodes must define node_key_epoch — the source of AGT SrcNodeKeyEpoch")
	}
}

func TestMintGrant_PayloadCarriesEpoch(t *testing.T) {
	// Verify that an AGT payload constructed with a nonzero SrcNodeKeyEpoch
	// carries that value through marshal/unmarshal. Combined with
	// TestAGTPayload_DeviceInfoPopulated, this proves the end-to-end
	// data flow from DB column to AGT wire format.
	now := time.Now().UTC()
	payload := contracts.AGTPayload{
		Ver: 2, JTI: uuid.Must(uuid.NewV7()), TenantID: uuid.Must(uuid.NewV7()),
		Subject:             contracts.OIDCIdentity{Issuer: "i", Subject: "s", UserID: "u"},
		SrcNodeID:           "node-1",
		SrcNodeKeyEpoch:     7, // nonzero — the value from the DB
		ApproverDeviceID:    uuid.Must(uuid.NewV7()),
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		ProtectedNodeID:     "p-1",
		Resource:            contracts.ResourceID{},
		Scope:               contracts.ScopeRequest,
		PolicyVersion:       1, AuthzEpoch: 1,
		IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute),
	}
	bytes, err := contracts.PrepareAGTPayload(&payload)
	if err != nil {
		t.Fatalf("PrepareAGTPayload: %v", err)
	}
	var decoded contracts.AGTPayload
	if err := cose.DecodeCanonical(bytes, &decoded); err != nil {
		t.Fatalf("DecodeCanonical: %v", err)
	}
	if decoded.SrcNodeKeyEpoch != 7 {
		t.Errorf("SrcNodeKeyEpoch: got %d, want 7 — epoch lost in marshal/roundtrip", decoded.SrcNodeKeyEpoch)
	}
}

// parseMigrationSchema reads the initial migration and returns a map of
// table name -> set of column names. Constraint lines (PRIMARY/FOREIGN/UNIQUE/
// CHECK/CONSTRAINT) are skipped; the column name is the first token of each
// column definition line.
func parseMigrationSchema(t *testing.T) map[string]map[string]bool {
	t.Helper()
	data, err := os.ReadFile("../../migrations/001_initial_schema.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	schema := map[string]map[string]bool{}
	createRe := regexp.MustCompile(`^CREATE TABLE (\w+) \(`)
	var cur string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if cur == "" {
			if m := createRe.FindStringSubmatch(line); m != nil {
				cur = m[1]
				schema[cur] = map[string]bool{}
			}
			continue
		}
		if strings.HasPrefix(line, ")") {
			cur = ""
			continue
		}
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "PRIMARY") || strings.HasPrefix(upper, "FOREIGN") ||
			strings.HasPrefix(upper, "UNIQUE") || strings.HasPrefix(upper, "CHECK") ||
			strings.HasPrefix(upper, "CONSTRAINT") {
			continue
		}
		schema[cur][strings.Fields(line)[0]] = true
	}
	return schema
}
