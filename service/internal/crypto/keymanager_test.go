package crypto

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestInMemoryEncrypterRoundTrip(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7())

	plaintext := []byte("sensitive data for tenant encryption")

	ciphertext, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Ciphertext must differ from plaintext
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Error("ciphertext should not equal plaintext (no encryption applied)")
	}

	decrypted, err := enc.Decrypt(ctx, tenantID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %x, want %x", decrypted, plaintext)
	}
}

func TestInMemoryEncrypterTamperDetection(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7())
	plaintext := []byte("tamper-me-if-you-can")

	ciphertext, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Flip a byte in the ciphertext body (after nonce)
	nonceSize := 12 // AES-256-GCM nonce size
	if len(ciphertext) > nonceSize+1 {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[nonceSize] ^= 0x01

		_, err := enc.Decrypt(ctx, tenantID, tampered)
		if err == nil {
			t.Error("decryption of tampered ciphertext should fail")
		}
	}
}

func TestInMemoryEncrypterNonceUniqueness(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7())
	plaintext := []byte("same plaintext")

	ct1, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	ct2, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of same plaintext should produce different ciphertext (nonce reuse)")
	}
}

func TestInMemoryEncrypterCrossTenantIsolation(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantA := uuid.Must(uuid.NewV7())
	tenantB := uuid.Must(uuid.NewV7())
	plaintext := []byte("tenant-specific data")

	ciphertext, err := enc.Encrypt(ctx, tenantA, plaintext)
	if err != nil {
		t.Fatalf("Encrypt for tenant A failed: %v", err)
	}

	// Decrypting with tenant B should fail (different key)
	_, err = enc.Decrypt(ctx, tenantB, ciphertext)
	if err == nil {
		t.Error("decryption with wrong tenant key should fail")
	}
}

func TestInMemoryEncrypterEmptyPlaintext(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7())

	ciphertext, err := enc.Encrypt(ctx, tenantID, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}

	decrypted, err := enc.Decrypt(ctx, tenantID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty decryption, got %x", decrypted)
	}
}

func TestInMemoryEncrypterLargePlaintext(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7())

	plaintext := make([]byte, 1024*1024) // 1 MiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := enc.Encrypt(ctx, tenantID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt large failed: %v", err)
	}

	decrypted, err := enc.Decrypt(ctx, tenantID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt large failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large plaintext round-trip failed")
	}
}

func TestInMemoryEncrypterTruncatedCiphertext(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7())

	// Ciphertext shorter than nonce size should fail
	_, err := enc.Decrypt(ctx, tenantID, []byte{0x00})
	if err == nil {
		t.Error("decryption of truncated ciphertext should fail")
	}
}

func TestInMemoryEncrypterCiphertextExpansion(t *testing.T) {
	enc := NewInMemoryEncrypter()
	ctx := context.Background()
	tenantID := uuid.Must(uuid.NewV7())

	for _, size := range []int{0, 1, 16, 256, 4096} {
		plaintext := make([]byte, size)

		ciphertext, err := enc.Encrypt(ctx, tenantID, plaintext)
		if err != nil {
			t.Fatalf("encrypt size %d failed: %v", size, err)
		}

		// AES-256-GCM: nonce (12 bytes) + plaintext + tag (16 bytes)
		expectedMinLen := 12 + len(plaintext) + 16
		if len(ciphertext) != expectedMinLen {
			t.Errorf("size %d: expected ciphertext len %d, got %d", size, expectedMinLen, len(ciphertext))
		}

		decrypted, err := enc.Decrypt(ctx, tenantID, ciphertext)
		if err != nil {
			t.Fatalf("decrypt size %d failed: %v", size, err)
		}

		if len(decrypted) != size {
			t.Errorf("size %d: expected decrypted len %d, got %d", size, size, len(decrypted))
		}
	}
}
