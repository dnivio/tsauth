package cose_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/dnivio/contracts/cose"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	type testMsg struct {
		Name  string `cbor:"1,keyasint"`
		Value int    `cbor:"2,keyasint"`
	}

	original := testMsg{Name: "test", Value: 42}
	encoded, err := cose.EncodeCanonical(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var decoded testMsg
	if err := cose.DecodeCanonical(encoded, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Name != original.Name || decoded.Value != original.Value {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, original)
	}
}

func TestDeterministicEncoding(t *testing.T) {
	// Same data must produce identical bytes every time
	type msg struct {
		B int `cbor:"1,keyasint"`
		A int `cbor:"2,keyasint"`
	}

	m := msg{A: 1, B: 2}

	encoded1, err := cose.EncodeCanonical(m)
	if err != nil {
		t.Fatalf("encode1: %v", err)
	}

	encoded2, err := cose.EncodeCanonical(m)
	if err != nil {
		t.Fatalf("encode2: %v", err)
	}

	if len(encoded1) != len(encoded2) {
		t.Errorf("different lengths: %d vs %d", len(encoded1), len(encoded2))
	}
	for i := range encoded1 {
		if encoded1[i] != encoded2[i] {
			t.Errorf("byte %d differs: %x vs %x", i, encoded1[i], encoded2[i])
			break
		}
	}
}

func TestSign1AndVerify(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	payload := []byte("Dnivio test payload")
	kid := "test-key-1"
	typ := "dnivio-test-v1"

	msg, err := cose.Sign1(priv, kid, typ, payload, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if msg.Protected.Algorithm != cose.AlgorithmEdDSA {
		t.Errorf("expected EdDSA algorithm, got %d", msg.Protected.Algorithm)
	}
	if msg.Protected.KeyID != kid {
		t.Errorf("expected kid %q, got %q", kid, msg.Protected.KeyID)
	}
	if msg.Protected.Type != typ {
		t.Errorf("expected type %q, got %q", typ, msg.Protected.Type)
	}

	// Verify
	verifiedPayload, headers, err := cose.Verify1(msg, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if string(verifiedPayload) != string(payload) {
		t.Errorf("payload mismatch: got %q, want %q", verifiedPayload, payload)
	}
	if headers.KeyID != kid {
		t.Errorf("header kid mismatch: got %q, want %q", headers.KeyID, kid)
	}
}

func TestSign1VerifyWrongKey(t *testing.T) {
	_, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	wrongPub, _, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}

	msg, err := cose.Sign1(priv, "kid", "typ", []byte("test"), nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, _, err = cose.Verify1(msg, wrongPub)
	if err == nil {
		t.Error("expected verification failure with wrong key")
	}
}

func TestSign1TamperedPayload(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	msg, err := cose.Sign1(priv, "kid", "typ", []byte("original"), nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tamper with payload
	msg.Payload = []byte("tampered")

	_, _, err = cose.Verify1(msg, pub)
	if err == nil {
		t.Error("expected verification failure with tampered payload")
	}
}

func TestSerializeDeserializeSign1(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	msg, err := cose.Sign1(priv, "kid1", "dnivio-agt-v2", []byte("payload"), nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	serialized, err := cose.SerializeSign1(msg)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	deserialized, err := cose.DeserializeSign1(serialized)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	_, _, err = cose.Verify1(deserialized, pub)
	if err != nil {
		t.Fatalf("verify after roundtrip: %v", err)
	}
}

func TestLowSCheck(t *testing.T) {
	// A DER signature with high-S (s > N/2)
	// This is a synthetic test since we can't generate one easily
	// The function should at minimum handle short/malformed input gracefully
	if cose.IsLowS([]byte{}) {
		t.Error("empty signature should not be low-S")
	}
	if cose.IsLowS([]byte{0x00}) {
		t.Error("single-byte signature should not be low-S")
	}
}

func TestDecodeMalformedRejected(t *testing.T) {
	// Garbage data should be rejected
	_, err := cose.DeserializeSign1([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Error("expected error decoding garbage")
	}
}

func TestGenerateKey(t *testing.T) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	// Verify keys are a valid pair
	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("generated key pair does not verify")
	}
}
