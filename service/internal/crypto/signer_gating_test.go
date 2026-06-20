package crypto

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
)

// ─── C5: Production signer gating ──────────────────────────────────────────

func TestNewSignerForMode_DevModeAllowsInMemory(t *testing.T) {
	signer, err := NewSignerForMode(true, "")
	if err != nil {
		t.Fatalf("dev mode should allow InMemorySigner: %v", err)
	}
	if signer == nil {
		t.Fatal("signer should not be nil in dev mode")
	}
	// Verify it's actually functional
	kid, pub, err := signer.GenerateKey(context.Background(), PurposeRequestSig)
	if err != nil {
		t.Fatalf("dev signer GenerateKey failed: %v", err)
	}
	if kid == "" || pub == nil {
		t.Error("dev signer returned empty kid or nil pub key")
	}
}

func TestNewSignerForMode_ProductionRejectsWithoutVault(t *testing.T) {
	signer, err := NewSignerForMode(false, "")
	if err == nil {
		t.Fatal("production mode with empty vault addr should return error")
	}
	if signer != nil {
		t.Error("signer must be nil when error is returned")
	}
}

func TestNewSignerForMode_ProductionRejectsWithoutImplementation(t *testing.T) {
	// Even with a vault addr, production should fail until Vault Transit is implemented
	signer, err := NewSignerForMode(false, "https://vault.internal:8200")
	if err == nil {
		t.Fatal("production mode should fail until Vault Transit signer is implemented")
	}
	if signer != nil {
		t.Error("signer must be nil when Vault is not yet implemented")
	}
}

// ─── C5: Root public key loading ───────────────────────────────────────────

func TestLoadRootPubKey_ValidHexKey(t *testing.T) {
	pub, _, _, err := NewRootKey()
	if err != nil {
		t.Fatalf("NewRootKey: %v", err)
	}
	hexKey := fmt.Sprintf("%x\n", pub)

	tmpFile := t.TempDir() + "/root.pub"
	if err := os.WriteFile(tmpFile, []byte(hexKey), 0600); err != nil {
		t.Fatalf("write temp key: %v", err)
	}

	loaded, fp, err := LoadRootPubKey(tmpFile)
	if err != nil {
		t.Fatalf("LoadRootPubKey: %v", err)
	}
	if !bytes.Equal(loaded, pub) {
		t.Error("loaded key does not match original")
	}
	if fp == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestLoadRootPubKey_MissingFile(t *testing.T) {
	_, _, err := LoadRootPubKey("/nonexistent/path/to/key.pub")
	if err == nil {
		t.Fatal("missing file should return error")
	}
}

func TestLoadRootPubKey_EmptyPath(t *testing.T) {
	_, _, err := LoadRootPubKey("")
	if err == nil {
		t.Fatal("empty path should return error")
	}
}

func TestLoadRootPubKey_InvalidHex(t *testing.T) {
	tmpFile := t.TempDir() + "/bad.pub"
	if err := os.WriteFile(tmpFile, []byte("not-a-hex-key"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := LoadRootPubKey(tmpFile)
	if err == nil {
		t.Fatal("invalid hex should return error")
	}
}

func TestLoadRootPubKey_WrongSize(t *testing.T) {
	tmpFile := t.TempDir() + "/short.pub"
	if err := os.WriteFile(tmpFile, []byte("aabbccdd"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := LoadRootPubKey(tmpFile)
	if err == nil {
		t.Fatal("wrong-size key should return error")
	}
}

// ─── C5/C6: Encrypter production gate ─────────────────────────────────────

func TestInMemoryEncrypter_DevOnlyMarker(t *testing.T) {
	enc := NewInMemoryEncrypter()
	if enc == nil {
		t.Fatal("NewInMemoryEncrypter returned nil")
	}
	ctx := context.Background()
	tid := uuid.Must(uuid.NewV7())
	ct, err := enc.Encrypt(ctx, tid, []byte("test"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct) <= len("test") {
		t.Error("ciphertext should be longer than plaintext (nonce + tag must be present)")
	}
}

// --- C6: Encrypter production gate ---
func TestNewEncrypterForMode_DevModeAllowsInMemory(t *testing.T) {
	enc, err := NewEncrypterForMode(true, "")
	if err != nil {
		t.Fatalf("dev mode should allow InMemoryEncrypter: %v", err)
	}
	if enc == nil {
		t.Fatal("encrypter should not be nil in dev mode")
	}
}

func TestNewEncrypterForMode_ProductionRejectsWithoutVault(t *testing.T) {
	enc, err := NewEncrypterForMode(false, "")
	if err == nil {
		t.Fatal("production mode with empty vault addr should return error")
	}
	if enc != nil {
		t.Error("encrypter must be nil when error is returned")
	}
}

func TestNewEncrypterForMode_ProductionRejectsWithoutImpl(t *testing.T) {
	enc, err := NewEncrypterForMode(false, "https://vault.internal:8200")
	if err == nil {
		t.Fatal("production mode should fail until Vault encrypter is implemented")
	}
	if enc != nil {
		t.Error("encrypter must be nil when not yet implemented")
	}
}

// --- C6: Combined production init path ---

func TestInitCrypto_DevModeAllowsBoth(t *testing.T) {
	signer, enc, err := InitCrypto(true, "")
	if err != nil {
		t.Fatalf("dev mode should allow both signer and encrypter: %v", err)
	}
	if signer == nil || enc == nil {
		t.Fatal("both signer and encrypter must be non-nil in dev mode")
	}
}

func TestInitCrypto_ProductionRejectsBoth(t *testing.T) {
	signer, enc, err := InitCrypto(false, "")
	if err == nil {
		t.Fatal("production mode without Vault must reject init")
	}
	if signer != nil || enc != nil {
		t.Error("both signer and encrypter must be nil on error")
	}
}

func TestInitCrypto_ProductionRejectsWithoutImplementation(t *testing.T) {
	signer, enc, err := InitCrypto(false, "https://vault.internal:8200")
	if err == nil {
		t.Fatal("production mode must reject until Vault is implemented")
	}
	if signer != nil || enc != nil {
		t.Error("both signer and encrypter must be nil when Vault is not implemented")
	}
}
