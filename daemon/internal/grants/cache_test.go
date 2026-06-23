package grants

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/dnivio/contracts"
	"github.com/dnivio/contracts/cose"
	"github.com/google/uuid"
)

// ─── C2: AGT signature verification ───────────────────────────────────────

func TestVerifyAndStore_ValidAGT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	nodeID := uuid.Must(uuid.NewV7())
	deviceID := uuid.Must(uuid.NewV7())
	jti := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()

	payload := &contracts.AGTPayload{
		Ver:    2,
		JTI:    jti,
		TenantID: tenantID,
		Subject: contracts.OIDCIdentity{
			Issuer:  "https://idp.example.com",
			Subject: "user-123",
			UserID:  userID.String(),
		},
		SrcNodeID:           "node-src-1",
		SrcNodeKeyEpoch:     1,
		ApproverDeviceID:    deviceID,
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		ProtectedNodeID:     nodeID.String(),
		Resource: contracts.ResourceID{
			TenantID:        tenantID,
			ProtectedNodeID: nodeID.String(),
			ServiceID:       "web-app",
			Port:            443,
			Transport:       contracts.TransportTCP,
			DeploymentMode:  contracts.ModeHTTPProxy,
		},
		Protocol:       "HTTPS",
		DeploymentMode: "HTTP_PROXY",
		Scope:          contracts.ScopeRequest,
		Binding:        contracts.ScopeBinding{HTTPRequest: &contracts.HTTPRequestBinding{RequestNonce: []byte("nonce-abc")}},
		PolicyVersion:  5,
		RuleID:         "rule-1",
		AuthzEpoch:     3,
		IssuedAt:       now,
		NotBefore:      now,
		ExpiresAt:      now.Add(30 * time.Second),
	}

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// VerifyAndStore with correct trust root and current state
	entry, err := VerifyAndStore(rawAGT, pub, 3, 5, contracts.SensitivityStandard)
	if err != nil {
		t.Fatalf("VerifyAndStore valid AGT failed: %v", err)
	}
	if entry == nil {
		t.Fatal("entry should not be nil")
	}
	if entry.JTI != jti {
		t.Errorf("JTI mismatch: got %s want %s", entry.JTI, jti)
	}
}

func TestVerifyAndStore_WrongSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// Verify with WRONG trust root
	_, err = VerifyAndStore(rawAGT, wrongPub, 1, 1, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("verification with wrong trust root should fail")
	}
}

func TestVerifyAndStore_ExpiredAGT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	payload.ExpiresAt = now.Add(-1 * time.Minute) // expired

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	_, err = VerifyAndStore(rawAGT, pub, 1, 1, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("expired AGT should be rejected")
	}
}

func TestVerifyAndStore_NotYetValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	payload.NotBefore = now.Add(1 * time.Hour) // future nbf

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	_, err = VerifyAndStore(rawAGT, pub, 1, 1, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("not-yet-valid AGT should be rejected")
	}
}

func TestVerifyAndStore_StalePolicyVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	payload.PolicyVersion = 2 // AGT says version 2

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// Current policy version is 5 (newer than AGT's 2)
	_, err = VerifyAndStore(rawAGT, pub, 3, 5, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("stale policy version should be rejected")
	}
}

func TestVerifyAndStore_WrongEpoch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	payload.AuthzEpoch = 1

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	_, err = VerifyAndStore(rawAGT, pub, 2, 5, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("wrong authz epoch should be rejected")
	}
}

func TestVerifyAndStore_InsufficientSecurityLevel(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	payload.DeviceSecurityLevel = string(contracts.SecurityLevelTEE) // only TEE

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// Current sensitivity is HIGH (requires StrongBox)
	_, err = VerifyAndStore(rawAGT, pub, 1, 1, contracts.SensitivityHigh)
	if err == nil {
		t.Fatal("insufficient security level should be rejected for HIGH sensitivity")
	}
}

func TestVerifyAndStore_TamperedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)

	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// Tamper with the raw bytes (flip a byte in the payload section)
	tampered := make([]byte, len(rawAGT))
	copy(tampered, rawAGT)
	// Flip a byte in the CBOR payload (after the protected headers and sig structure)
	if len(tampered) > 50 {
		tampered[40] ^= 0x01
	}

	_, err = VerifyAndStore(tampered, pub, 1, 1, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("tampered AGT should be rejected")
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func signAGT(signer ed25519.PrivateKey, typ string, payload *contracts.AGTPayload) ([]byte, error) {
	payloadBytes, err := contracts.PrepareAGTPayload(payload)
	if err != nil {
		return nil, err
	}
	msg, err := cose.Sign1(signer, "", typ, payloadBytes, nil)
	if err != nil {
		return nil, err
	}
	return cose.SerializeSign1(msg)
}

func validAGTPayload(now time.Time) *contracts.AGTPayload {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	nodeID := uuid.Must(uuid.NewV7())
	deviceID := uuid.Must(uuid.NewV7())

	return &contracts.AGTPayload{
		Ver:    2,
		JTI:    uuid.Must(uuid.NewV7()),
		TenantID: tenantID,
		Subject: contracts.OIDCIdentity{
			Issuer:  "https://idp.example.com",
			Subject: "user-123",
			UserID:  userID.String(),
		},
		SrcNodeID:           "node-src-1",
		SrcNodeKeyEpoch:     1,
		ApproverDeviceID:    deviceID,
		DeviceSecurityLevel: string(contracts.SecurityLevelStrongBox),
		ProtectedNodeID:     nodeID.String(),
		Resource: contracts.ResourceID{
			TenantID:        tenantID,
			ProtectedNodeID: nodeID.String(),
			ServiceID:       "web-app",
			Port:            443,
			Transport:       contracts.TransportTCP,
			DeploymentMode:  contracts.ModeHTTPProxy,
		},
		Protocol:       "HTTPS",
		DeploymentMode: "HTTP_PROXY",
		Scope:          contracts.ScopeRequest,
		Binding: contracts.ScopeBinding{
			HTTPRequest: &contracts.HTTPRequestBinding{RequestNonce: []byte("nonce-abc")},
		},
		PolicyVersion: 1,
		RuleID:        "rule-1",
		AuthzEpoch:    1,
		IssuedAt:      now,
		NotBefore:     now,
		ExpiresAt:     now.Add(30 * time.Second),
	}
}

// --- C2: Production-path AGT verification (StoreVerified) ---

func TestStoreVerified_RejectsForgedAGT(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, forgedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate forged key: %v", err)
	}

	// Create a valid AGT signed with forged key
	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(forgedPriv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// StoreVerified with the REAL trust root must reject the forged AGT
	cache, err := NewCache(t.TempDir()+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	err = cache.StoreVerified(rawAGT, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("StoreVerified must reject AGT signed with forged key")
	}
}

func TestStoreVerified_AcceptsValidAGT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	cache, err := NewCache(t.TempDir()+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	err = cache.StoreVerified(rawAGT, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard)
	if err != nil {
		t.Fatalf("StoreVerified valid AGT failed: %v", err)
	}

	// Verify the grant is now in the cache and can be found
	key := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%d/%s",
		payload.TenantID, payload.Subject.UserID, payload.SrcNodeID,
		payload.ProtectedNodeID, payload.Resource.ServiceID, payload.Protocol,
		payload.Scope, payload.PolicyVersion, "6e6f6e63652d616263")
	if _, ok := cache.Check(key); !ok {
		t.Fatal("grant not found in cache after StoreVerified")
	}
}

func TestStoreVerified_RejectsTamperedAGTBytes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// Tamper with raw bytes
	tampered := make([]byte, len(rawAGT))
	copy(tampered, rawAGT)
	if len(tampered) > 50 {
		tampered[40] ^= 0x01
	}

	cache, err := NewCache(t.TempDir()+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	// The tampered bytes must be rejected before entering the cache
	err = cache.StoreVerified(tampered, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard)
	if err == nil {
		t.Fatal("StoreVerified must reject tampered AGT bytes")
	}

	// Verify nothing entered the cache
	key := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%d/%s",
		payload.TenantID, payload.Subject.UserID, payload.SrcNodeID,
		payload.ProtectedNodeID, payload.Resource.ServiceID, payload.Protocol,
		payload.Scope, payload.PolicyVersion, "6e6f6e63652d616263")
	if _, ok := cache.Check(key); ok {
		t.Fatal("tampered AGT must not enter cache")
	}
}

// --- C4: Single-use grant consumption (remoteConsume callback) ---

func TestConsume_CallsRemoteConsume(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	cache, err := NewCache(t.TempDir()+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	var remoteCalled int
	cache.SetRemoteConsume(func(ctx context.Context, jti uuid.UUID) (bool, error) {
		remoteCalled++
		if jti != payload.JTI {
			return false, fmt.Errorf("unexpected JTI")
		}
		return true, nil
	})

	if err := cache.StoreVerified(rawAGT, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard); err != nil {
		t.Fatalf("StoreVerified: %v", err)
	}

	key := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%d/%s",
		payload.TenantID, payload.Subject.UserID, payload.SrcNodeID,
		payload.ProtectedNodeID, payload.Resource.ServiceID, payload.Protocol,
		payload.Scope, payload.PolicyVersion, "6e6f6e63652d616263")
	_, err = cache.Consume(context.Background(), key, payload.JTI)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if remoteCalled != 1 {
		t.Errorf("remoteConsume should be called once, got %d", remoteCalled)
	}
}

func TestConsume_FailsWithRemoteConsumeRejection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	cache, err := NewCache(t.TempDir()+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	cache.SetRemoteConsume(func(ctx context.Context, jti uuid.UUID) (bool, error) {
		return false, nil // server says already consumed
	})

	if err := cache.StoreVerified(rawAGT, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard); err != nil {
		t.Fatalf("StoreVerified: %v", err)
	}

	key := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%d/%s",
		payload.TenantID, payload.Subject.UserID, payload.SrcNodeID,
		payload.ProtectedNodeID, payload.Resource.ServiceID, payload.Protocol,
		payload.Scope, payload.PolicyVersion, "6e6f6e63652d616263")
	_, err = cache.Consume(context.Background(), key, payload.JTI)
	if err == nil {
		t.Fatal("Consume should fail when remote consumption is rejected")
	}
}

// --- H9: Grant cache persistence key and replay protection ---

func TestPersistentStorage_KeySurvivesRestart(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dir := t.TempDir()

	// First "process": store a grant
	cache1, err := NewCache(dir+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache 1: %v", err)
	}
	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}
	if err := cache1.StoreVerified(rawAGT, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard); err != nil {
		t.Fatalf("StoreVerified: %v", err)
	}

	// Simulate restart: create a new cache with same path
	cache2, err := NewCache(dir+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache 2: %v", err)
	}

	// Verify the grant is still found (persistence worked)
	key := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%d/%s",
		payload.TenantID, payload.Subject.UserID, payload.SrcNodeID,
		payload.ProtectedNodeID, payload.Resource.ServiceID, payload.Protocol,
		payload.Scope, payload.PolicyVersion, "6e6f6e63652d616263")
	if _, ok := cache2.Check(key); !ok {
		t.Fatal("H9 FAIL: grant not found after restart — persistence key changed")
	}
}

func TestConsume_RejectsReplayAfterRestart(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dir := t.TempDir()
	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// First process: store and consume
	cache1, err := NewCache(dir+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache 1: %v", err)
	}
	cache1.SetRemoteConsume(func(ctx context.Context, jti uuid.UUID) (bool, error) {
		return true, nil
	})
	if err := cache1.StoreVerified(rawAGT, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard); err != nil {
		t.Fatalf("StoreVerified: %v", err)
	}
	key := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%d/%s",
		payload.TenantID, payload.Subject.UserID, payload.SrcNodeID,
		payload.ProtectedNodeID, payload.Resource.ServiceID, payload.Protocol,
		payload.Scope, payload.PolicyVersion, "6e6f6e63652d616263")
	_, err = cache1.Consume(context.Background(), key, payload.JTI)
	if err != nil {
		t.Fatalf("Consume 1: %v", err)
	}

	// Simulate restart with same persistence files
	cache2, err := NewCache(dir+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache 2: %v", err)
	}
	cache2.SetRemoteConsume(func(ctx context.Context, jti uuid.UUID) (bool, error) {
		return true, nil
	})

	// Try to consume again — must fail (replay protection from persisted consumedJTIs)
	_, err = cache2.Consume(context.Background(), key, payload.JTI)
	if err == nil {
		t.Fatal("H9 FAIL: grant consumption succeeded after restart — replay not prevented")
	}
}

func TestCheck_RejectsConsumedAfterRestart(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dir := t.TempDir()
	now := time.Now().UTC()
	payload := validAGTPayload(now)
	rawAGT, err := signAGT(priv, "dnivio-agt-v2", payload)
	if err != nil {
		t.Fatalf("sign AGT: %v", err)
	}

	// First process: store and consume
	cache1, err := NewCache(dir+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache 1: %v", err)
	}
	cache1.SetRemoteConsume(func(ctx context.Context, jti uuid.UUID) (bool, error) {
		return true, nil
	})
	if err := cache1.StoreVerified(rawAGT, payload.AuthzEpoch, payload.PolicyVersion, contracts.SensitivityStandard); err != nil {
		t.Fatalf("StoreVerified: %v", err)
	}
	key := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%d/%s",
		payload.TenantID, payload.Subject.UserID, payload.SrcNodeID,
		payload.ProtectedNodeID, payload.Resource.ServiceID, payload.Protocol,
		payload.Scope, payload.PolicyVersion, "6e6f6e63652d616263")
	_, err = cache1.Consume(context.Background(), key, payload.JTI)
	if err != nil {
		t.Fatalf("Consume 1: %v", err)
	}

	// Simulate restart — Check must also reject consumed grants
	cache2, err := NewCache(dir+"/grants.db", pub)
	if err != nil {
		t.Fatalf("NewCache 2: %v", err)
	}

	if _, ok := cache2.Check(key); ok {
		t.Fatal("H9 FAIL: Check returned ok for consumed grant after restart")
	}
}
