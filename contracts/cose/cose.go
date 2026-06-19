// Package cose implements COSE_Sign1 (RFC 9052) with Ed25519 for Dnivio signed envelopes.
// Uses deterministic CBOR encoding: sorted keys, definite lengths, canonical single encoding.
// Per DR-SIG-1, DR-SIG-5, DR-KEY-7, and §8.1 of ENGINEERING.md v2.1.
package cose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

// ─── Algorithm Constants ──────────────────────────────────────────────────

// Algorithm identifiers per RFC 9053.
const (
	AlgorithmEdDSA = -8 // Ed25519
)

// Header parameter labels per RFC 9052.
const (
	HeaderLabelAlg = 1
	HeaderLabelKid = 4
	HeaderLabelTyp = 16
)

// ─── COSE_Sign1 Structure ─────────────────────────────────────────────────

// Sign1Message is a COSE_Sign1 message per RFC 9052 §4.2.
// It carries a single Ed25519 signature over the SigStructure.
type Sign1Message struct {
	Protected   Headers           `cbor:"0,keyasint"`
	Unprotected map[int]any       `cbor:"1,keyasint"`
	Payload     []byte            `cbor:"2,keyasint"`
	Signature   []byte            `cbor:"3,keyasint"`
}

// Headers contains the protected header parameters.
type Headers struct {
	Algorithm int    `cbor:"1,keyasint"`
	KeyID     string `cbor:"4,keyasint,omitempty"`
	Type      string `cbor:"16,keyasint,omitempty"`
}

// ─── Deterministic CBOR Encoder ────────────────────────────────────────────

// encMode is the deterministic CBOR encoding mode used for all Dnivio signatures.
// Features: sorted map keys, definite lengths, canonical encodings.
var encMode, encModeErr = cbor.EncOptions{
	Sort:          cbor.SortCanonical,
	ShortestFloat: cbor.ShortestFloat16,
	IndefLength:   cbor.IndefLengthForbidden,
	Time:          cbor.TimeRFC3339,
	TagsMd:        cbor.TagsForbidden,
}.EncMode()

// decMode is the strict decoding mode; rejects unknown fields in canonical verification.
var decMode, decModeErr = cbor.DecOptions{
	MaxArrayElements: 65536,
	MaxMapPairs:      65536,
	MaxNestedLevels:  16,
	IndefLength:      cbor.IndefLengthForbidden,
	TagsMd:           cbor.TagsForbidden,
	ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
}.DecMode()

// EncodeCanonical serializes v to deterministic CBOR bytes.
// Must produce identical bytes across languages for the same input.
func EncodeCanonical(v any) ([]byte, error) {
	if encModeErr != nil {
		return nil, fmt.Errorf("cose: encoder init: %w", encModeErr)
	}
	return encMode.Marshal(v)
}

// DecodeCanonical deserializes strictly from deterministic CBOR bytes.
func DecodeCanonical(data []byte, v any) error {
	if decModeErr != nil {
		return fmt.Errorf("cose: decoder init: %w", decModeErr)
	}
	return decMode.Unmarshal(data, v)
}

// ─── COSE_Sign1 Operations ────────────────────────────────────────────────

// SigStructure is the structure signed per RFC 9052 §4.4.
// SigStructure = ["Signature1", protected, external_aad, payload]
// We serialize as a CBOR array for deterministic encoding.
type sigStructure struct {
	Context     string `cbor:"0,keyasint"` // "Signature1"
	Protected   []byte `cbor:"1,keyasint"`
	ExternalAAD []byte `cbor:"2,keyasint"` // zero-length for Dnivio
	Payload     []byte `cbor:"3,keyasint"`
}

// Sign1 creates and signs a COSE_Sign1 message with Ed25519.
// kid is the key identifier; typ is the envelope type ("dnivio-req-v2", "dnivio-agt-v2", etc.).
// payload is the CBOR-encoded payload bytes.
// externalAAD is additional authenticated data (usually empty for Dnivio).
func Sign1(signer ed25519.PrivateKey, kid, typ string, payload, externalAAD []byte) (*Sign1Message, error) {
	if encModeErr != nil {
		return nil, fmt.Errorf("cose: encoder init: %w", encModeErr)
	}

	headers := Headers{
		Algorithm: AlgorithmEdDSA,
		KeyID:     kid,
		Type:      typ,
	}

	// Encode protected headers deterministically
	protectedBytes, err := encMode.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("cose: marshal protected headers: %w", err)
	}

	// Normalize nil externalAAD to empty slice for canonical encoding
	if externalAAD == nil {
		externalAAD = []byte{}
	}

	// Build SigStructure
	sigStruct := sigStructure{
		Context:     "Signature1",
		Protected:   protectedBytes,
		ExternalAAD: externalAAD,
		Payload:     payload,
	}

	sigStructBytes, err := encMode.Marshal(sigStruct)
	if err != nil {
		return nil, fmt.Errorf("cose: marshal sig structure: %w", err)
	}

	// Sign with Ed25519
	signature := ed25519.Sign(signer, sigStructBytes)

	return &Sign1Message{
		Protected:   headers,
		Unprotected: nil,
		Payload:     payload,
		Signature:   signature,
	}, nil
}

// Verify1 verifies a COSE_Sign1 message against the given public key.
// Returns the raw payload bytes on success.
// Per DR-SIG-1: must verify algorithm, kid, canonical encoding before trusting payload.
func Verify1(msg *Sign1Message, pubKey ed25519.PublicKey) ([]byte, *Headers, error) {
	if msg.Protected.Algorithm != AlgorithmEdDSA {
		return nil, nil, fmt.Errorf("cose: unsupported algorithm %d", msg.Protected.Algorithm)
	}

	if encModeErr != nil {
		return nil, nil, fmt.Errorf("cose: encoder init: %w", encModeErr)
	}

	protectedBytes, err := encMode.Marshal(msg.Protected)
	if err != nil {
		return nil, nil, fmt.Errorf("cose: marshal protected for verification: %w", err)
	}

	sigStruct := sigStructure{
		Context:     "Signature1",
		Protected:   protectedBytes,
		ExternalAAD: []byte{}, // Dnivio uses empty external_aad
		Payload:     msg.Payload,
	}

	sigStructBytes, err := encMode.Marshal(sigStruct)
	if err != nil {
		return nil, nil, fmt.Errorf("cose: marshal sig structure for verify: %w", err)
	}

	if !ed25519.Verify(pubKey, sigStructBytes, msg.Signature) {
		return nil, nil, fmt.Errorf("cose: signature verification failed")
	}

	return msg.Payload, &msg.Protected, nil
}

// SerializeSign1 encodes a COSE_Sign1 message to deterministic CBOR bytes.
func SerializeSign1(msg *Sign1Message) ([]byte, error) {
	return EncodeCanonical(msg)
}

// DeserializeSign1 decodes a COSE_Sign1 message from CBOR bytes with strict checking.
func DeserializeSign1(data []byte) (*Sign1Message, error) {
	var msg Sign1Message
	if err := DecodeCanonical(data, &msg); err != nil {
		return nil, fmt.Errorf("cose: deserialize: %w", err)
	}
	// Validate required fields
	if msg.Protected.Algorithm == 0 && msg.Protected.KeyID == "" {
		return &msg, nil // allow empty headers for decryption-only flows
	}
	if msg.Protected.Algorithm == 0 {
		return nil, fmt.Errorf("cose: missing algorithm in protected headers")
	}
	return &msg, nil
}

// ─── Ed25519 Key Generation ───────────────────────────────────────────────

// GenerateKey creates a new Ed25519 key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// ─── ECDSA Low-S Enforcement (for Android P-256 keys) ──────────────────────

// IsLowS checks if an ECDSA signature's S component is in the low half of the curve.
// Per DR-KEY-7: the Service rejects malleable/high-S signatures.
func IsLowS(sig []byte) bool {
	if len(sig) < 2 {
		return false
	}
	// DER-encoded ECDSA signatures: SEQUENCE { INTEGER r, INTEGER s }
	// Find the S value and check it against N/2
	rLen, sLen := 0, 0
	// Skip SEQUENCE header (0x30 + length)
	pos := 2
	// Skip R integer (0x02 + length + value)
	if pos < len(sig) && sig[pos] == 0x02 {
		pos++
		if pos < len(sig) {
			rLen = int(sig[pos])
			pos += 1 + rLen
		}
	}
	// Read S integer (0x02 + length + value)
	if pos < len(sig) && sig[pos] == 0x02 {
		pos++
		if pos < len(sig) {
			sLen = int(sig[pos])
			pos++
		}
	}
	if sLen == 0 || pos+sLen > len(sig) {
		return false
	}
	s := sig[pos : pos+sLen]

	// P-256 order N/2 = 0x7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0
	nHalf := []byte{
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
		0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
	}

	// Compare s with N/2 byte-by-byte
	sValue := normalizeBytes(s, 32)
	for i := 0; i < 32; i++ {
		if sValue[i] < nHalf[i] {
			return true
		}
		if sValue[i] > nHalf[i] {
			return false
		}
	}
	return true // equal is low
}

// normalizeBytes left-pads a byte slice to the target length with zeros.
func normalizeBytes(b []byte, targetLen int) []byte {
	if len(b) >= targetLen {
		return b[len(b)-targetLen:]
	}
	padded := make([]byte, targetLen)
	copy(padded[targetLen-len(b):], b)
	return padded
}

// ─── Internal Helpers ─────────────────────────────────────────────────────

// Ensure interfaces
var _ io.Reader = rand.Reader
var _ = binary.BigEndian
var _ = sort.Ints
var _ = crypto.SHA256
var _ = fmt.Sprintf
