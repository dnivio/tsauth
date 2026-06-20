package enforcement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dnivio/contracts"
	"github.com/dnivio/contracts/cose"
	"github.com/dnivio/approval-service/internal/audit"
	"github.com/dnivio/approval-service/internal/crypto"
	"github.com/dnivio/approval-service/internal/messaging"
	"github.com/google/uuid"
)

// TestProcessApproval_EpochFlowsToAGT is the C8 production-path test.
func TestProcessApproval_EpochFlowsToAGT(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "grant_sig-test"

	ts := newTestSigner(kid, priv, pub)
	engine := NewApprovalEngine(db,
		audit.NewChainWriter(db, &stubAuditSigner{key: priv}),
		messaging.NewOutboxWriter(db),
		messaging.NewDeliveryStream(db),
		&stubRequestSigner{kmSigner: ts, kid: kid},
		&stubGrantSigner{kmSigner: ts, kid: kid}, nil,
	)

	tenantID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	resourceID := uuid.Must(uuid.NewV7())
	deviceID := uuid.Must(uuid.NewV7())
	nodeID := uuid.Must(uuid.NewV7())
	dbEpoch := int64(7) // nonzero epoch from DB

	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT ar\\.state.*node_key_epoch.*FROM approval_requests").
		WithArgs(tenantID, requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "state_version", "user_id", "resource_id", "scope", "binding",
			"policy_version", "rule_id", "src_node_id", "src_node_key_epoch",
		}).AddRow("PENDING", 1, userID, resourceID, "REQUEST", []byte{},
			int64(1), "rule-1", "node-1", dbEpoch))
	mock.ExpectQuery("(?s).*COALESCE.*").
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(3)))
	mock.ExpectQuery("(?s).*counter, approval_auth_pub.*").
		WithArgs(tenantID, deviceID).
		WillReturnRows(sqlmock.NewRows([]string{"counter", "approval_auth_pub", "device_auth_pub"}).
			AddRow(int64(0), []byte(pub), []byte(pub)))

	// Remaining DB calls
	mock.ExpectExec("(?s).*").WillReturnResult(sqlmock.NewResult(0, 1)) // transition
	mock.ExpectExec("(?s).*").WillReturnResult(sqlmock.NewResult(0, 1)) // UPDATE response
	mock.ExpectExec("(?s).*").WillReturnResult(sqlmock.NewResult(0, 1)) // advance counter
	// resolveUserIdentity (3 cols)
	mock.ExpectQuery("(?s).*oidc_issuer.*").WithArgs(tenantID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"a","b","c"}).AddRow("idp","sub",userID.String()))
	// getResourceDetails (5 cols)
	mock.ExpectQuery("(?s).*protected_node_id.*service_id.*").WithArgs(tenantID, resourceID).
		WillReturnRows(sqlmock.NewRows([]string{"a","b","c","d","e"}).AddRow(nodeID,"svc",443,"HTTP_PROXY","STANDARD"))
	// INSERT grant, UPDATE GRANTED, audit, outbox (rest)
	for i := 0; i < 1; i++ {
		mock.ExpectExec("(?s).*").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("(?s).*").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("(?s).*").WillReturnRows(sqlmock.NewRows([]string{"x"}).AddRow(int64(0)))
	}
	mock.ExpectCommit()

	reqHash := sha256.Sum256([]byte("test"))
	respNonce := make([]byte, 32)
	rand.Read(respNonce)
	approvalResp := &contracts.ApprovalResponse{
		RequestID:      requestID,
		Decision:       contracts.DecisionApprove,
		DeviceID:       deviceID,
		KeyID:          "approval_auth",
		DeviceCounter:  42,
		ChannelBinding: []byte("ch"),
		ResponseNonce:  respNonce,
		RequestHash:    reqHash[:],
	}
	contracts.SignApprovalResponse(priv, approvalResp)

	result, err := engine.ProcessApproval(context.Background(), ProcessApprovalInput{
		TenantID:       tenantID,
		RequestID:      requestID,
		DeviceID:       deviceID,
		Decision:       contracts.DecisionApprove,
		SignedResponse: approvalResp,
	})
	if err != nil {
		t.Fatalf("ProcessApproval: %v", err)
	}

	agt, err := contracts.VerifyAccessGrantToken(result.AGTBytes, pub, 3, 1, contracts.SensitivityStandard)
	if err != nil {
		t.Fatalf("verify AGT: %v", err)
	}
	if agt.Payload.SrcNodeKeyEpoch == 0 {
		t.Errorf("C8 FAIL: AGT has SrcNodeKeyEpoch=0 - hardcoded placeholder still active")
	}
	if agt.Payload.SrcNodeKeyEpoch != dbEpoch {
		t.Errorf("C8 FAIL: AGT SrcNodeKeyEpoch=%d, expected %d from DB",
			agt.Payload.SrcNodeKeyEpoch, dbEpoch)
	}
	_ = nodeID
}

// TestProcessApproval_RejectsForgedSignature verifies C3.
func TestProcessApproval_RejectsForgedSignature(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, forgedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate forged key: %v", err)
	}
	kid := "grant_sig-test"

	ts := newTestSigner(kid, priv, pub)
	engine := NewApprovalEngine(db,
		audit.NewChainWriter(db, &stubAuditSigner{key: priv}),
		messaging.NewOutboxWriter(db),
		messaging.NewDeliveryStream(db),
		&stubRequestSigner{kmSigner: ts, kid: kid},
		&stubGrantSigner{kmSigner: ts, kid: kid}, nil,
	)

	tenantID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	resourceID := uuid.Must(uuid.NewV7())
	deviceID := uuid.Must(uuid.NewV7())

	mock.ExpectBegin()
	mock.ExpectQuery("(?s).*state, state_version.*").
		WithArgs(tenantID, requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"state", "state_version", "user_id", "resource_id", "scope", "binding",
			"policy_version", "rule_id", "src_node_id", "src_node_key_epoch",
		}).AddRow("PENDING", 1, userID, resourceID, "REQUEST", []byte{},
			int64(1), "rule-1", "node-1", int64(1)))
	mock.ExpectQuery("(?s).*COALESCE.*").
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(1)))
	mock.ExpectQuery("(?s).*counter, approval_auth_pub.*").
		WithArgs(tenantID, deviceID).
		WillReturnRows(sqlmock.NewRows([]string{"counter", "approval_auth_pub", "device_auth_pub"}).
			AddRow(int64(0), []byte(pub), []byte(pub)))
	mock.ExpectRollback()

	reqHash := sha256.Sum256([]byte("test"))
	respNonce := make([]byte, 32)
	rand.Read(respNonce)
	approvalResp := &contracts.ApprovalResponse{
		RequestID:      requestID,
		Decision:       contracts.DecisionApprove,
		DeviceID:       deviceID,
		KeyID:          "approval_auth",
		DeviceCounter:  42,
		ResponseNonce:  respNonce,
		RequestHash:    reqHash[:],
	}
	contracts.SignApprovalResponse(forgedPriv, approvalResp)

	_, err = engine.ProcessApproval(context.Background(), ProcessApprovalInput{
		TenantID:       tenantID,
		RequestID:      requestID,
		DeviceID:       deviceID,
		Decision:       contracts.DecisionApprove,
		SignedResponse: approvalResp,
	})
	if err == nil {
		t.Fatal("C3 FAIL: ProcessApproval accepted response signed with forged key")
	}
}

type testSigner struct {
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}
func newTestSigner(kid string, priv ed25519.PrivateKey, pub ed25519.PublicKey) *testSigner {
	return &testSigner{kid: kid, priv: priv, pub: pub}
}
func (s *testSigner) Sign(ctx context.Context, kid string, message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}
func (s *testSigner) GetPubKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	return s.pub, nil
}
func (s *testSigner) GenerateKey(ctx context.Context, purpose crypto.KeyPurpose) (string, ed25519.PublicKey, error) {
	return s.kid, s.pub, nil
}
func (s *testSigner) HealthCheck(ctx context.Context) error { return nil }

type stubAuditSigner struct{ key ed25519.PrivateKey }
func (s *stubAuditSigner) Sign(ctx context.Context, message []byte) ([]byte, string, error) {
	return ed25519.Sign(s.key, message), "audit-kid", nil
}

type stubRequestSigner struct {
	kmSigner crypto.Signer
	kid      string
}
func (s *stubRequestSigner) SignRequest(ctx context.Context, payload *contracts.RequestPayload) ([]byte, error) {
	payloadBytes, err := contracts.PrepareRequestPayload(payload)
	if err != nil {
		return nil, err
	}
	sigStruct, _, _, err := cose.BuildSigStructure(s.kid, "dnivio-req-v2", payloadBytes, nil)
	if err != nil {
		return nil, err
	}
	sig, err := s.kmSigner.Sign(ctx, s.kid, sigStruct)
	if err != nil {
		return nil, err
	}
	msg, err := cose.Sign1WithSignature(s.kid, "dnivio-req-v2", payloadBytes, nil, sig)
	if err != nil {
		return nil, err
	}
	return cose.SerializeSign1(msg)
}

type stubGrantSigner struct {
	kmSigner crypto.Signer
	kid      string
}
func (s *stubGrantSigner) SignGrant(ctx context.Context, payload *contracts.AGTPayload) ([]byte, error) {
	payloadBytes, err := contracts.PrepareAGTPayload(payload)
	if err != nil {
		return nil, err
	}
	sigStruct, _, _, err := cose.BuildSigStructure(s.kid, "dnivio-agt-v2", payloadBytes, nil)
	if err != nil {
		return nil, err
	}
	sig, err := s.kmSigner.Sign(ctx, s.kid, sigStruct)
	if err != nil {
		return nil, err
	}
	msg, err := cose.Sign1WithSignature(s.kid, "dnivio-agt-v2", payloadBytes, nil, sig)
	if err != nil {
		return nil, err
	}
	return cose.SerializeSign1(msg)
}
