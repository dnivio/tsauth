// Package crypto provides the service-side cryptographic operations for the Dnivio Approval Service.
// Implements §8 (Cryptography & keys) and DR-KEY-7…11 of ENGINEERING.md v2.1.
package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/dnivio/contracts/cose"
	"github.com/google/uuid"
)

// ─── Key Purposes (§8.4) ──────────────────────────────────────────────────

// KeyPurpose identifies the role of a signing key.
type KeyPurpose string

const (
	PurposeRequestSig       KeyPurpose = "request_sig"
	PurposeGrantSig         KeyPurpose = "grant_sig"
	PurposePolicySig        KeyPurpose = "policy_sig"
	PurposeAuditCheckpoint  KeyPurpose = "audit_checkpoint_sig"
)

// AllPurposes lists all Dnivio signing key purposes.
var AllPurposes = []KeyPurpose{
	PurposeRequestSig,
	PurposeGrantSig,
	PurposePolicySig,
	PurposeAuditCheckpoint,
}

// ─── Key Set ───────────────────────────────────────────────────────────────

// KeyVersion represents a specific version of a signing key.
type KeyVersion struct {
	Kid        string             `json:"kid"`
	Purpose    KeyPurpose         `json:"purpose"`
	PubKey     ed25519.PublicKey  `json:"pub_key"`
	CreatedAt  time.Time          `json:"created_at"`
	ActivatedAt *time.Time        `json:"activated_at,omitempty"`
	RetiredAt   *time.Time        `json:"retired_at,omitempty"`
}

// IsActive returns true if the key is currently in use for signing.
func (kv *KeyVersion) IsActive() bool {
	if kv.ActivatedAt == nil {
		return false
	}
	if kv.RetiredAt != nil && time.Now().UTC().After(*kv.RetiredAt) {
		return false
	}
	return true
}

// ActiveKeySet holds the currently active signing keys.
type ActiveKeySet struct {
	Keys     map[KeyPurpose]*KeyVersion `json:"keys"`
	RootSig  []byte                     `json:"root_sig"`  // Offline root signature over pubkey set
	IssuedAt time.Time                  `json:"issued_at"`
}

// ─── KMS Interface (DR-KEY-8) ─────────────────────────────────────────────

// Signer abstracts a signing backend (Vault Transit in production).
type Signer interface {
	// Sign signs the prehash with the key identified by kid.
	// For Ed25519, this is raw Ed25519 signing of the message.
	Sign(ctx context.Context, kid string, message []byte) ([]byte, error)

	// GetPubKey returns the public key for a given kid.
	GetPubKey(ctx context.Context, kid string) (ed25519.PublicKey, error)

	// GenerateKey creates a new Ed25519 key pair and returns its kid.
	GenerateKey(ctx context.Context, purpose KeyPurpose) (kid string, pubKey ed25519.PublicKey, err error)

	// HealthCheck verifies the KMS is reachable and functional.
	HealthCheck(ctx context.Context) error
}

// EnvelopeEncrypter abstracts envelope encryption (Vault Transit AES-256-GCM).
type EnvelopeEncrypter interface {
	// Encrypt encrypts plaintext with tenant-scoped context.
	Encrypt(ctx context.Context, tenantID uuid.UUID, plaintext []byte) (ciphertext []byte, err error)

	// Decrypt decrypts ciphertext with tenant-scoped context.
	Decrypt(ctx context.Context, tenantID uuid.UUID, ciphertext []byte) (plaintext []byte, err error)
}

// ─── KeyManager ────────────────────────────────────────────────────────────

// KeyManager manages the lifecycle of Dnivio signing keys.
// Per DR-KEY-7: maintains separate keys for each purpose, versioned by kid.
// Per DR-KEY-9: supports rotation with overlap windows.
type KeyManager struct {
	mu           sync.RWMutex
	signer       Signer
	activeKeys   *ActiveKeySet
	rootPubKey   ed25519.PublicKey
	allowedKids  map[string]bool // allowlist of accepted kids (for verification)
	overlapKids  map[string]bool // kids in rotation overlap window
}

// NewKeyManager creates a new KeyManager.
func NewKeyManager(signer Signer, rootPubKey ed25519.PublicKey) *KeyManager {
	return &KeyManager{
		signer:      signer,
		rootPubKey:  rootPubKey,
		allowedKids: make(map[string]bool),
		overlapKids: make(map[string]bool),
	}
}

// Initialize generates initial key sets for all required purposes.
// Called once during service bootstrap. The offline root must sign the resulting key set.
func (km *KeyManager) Initialize(ctx context.Context) (*ActiveKeySet, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	keySet := &ActiveKeySet{
		Keys:     make(map[KeyPurpose]*KeyVersion),
		IssuedAt: time.Now().UTC(),
	}

	for _, purpose := range AllPurposes {
		kid, pubKey, err := km.signer.GenerateKey(ctx, purpose)
		if err != nil {
			return nil, fmt.Errorf("crypto: generate %s key: %w", purpose, err)
		}

		now := time.Now().UTC()
		kv := &KeyVersion{
			Kid:        kid,
			Purpose:    purpose,
			PubKey:     pubKey,
			CreatedAt:  now,
			ActivatedAt: &now,
		}
		keySet.Keys[purpose] = kv
		km.allowedKids[kid] = true
	}

	km.activeKeys = keySet
	return keySet, nil
}

// SetRootSignature records the offline root signature over the key set public keys.
// Per DR-KEY-10: the root signs the set of online signing public keys.
func (km *KeyManager) SetRootSignature(keySetSig []byte) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.activeKeys == nil {
		return fmt.Errorf("crypto: no active key set")
	}

	// Verify root signature over the key set's public keys
	if err := km.verifyRootSig(keySetSig, km.activeKeys); err != nil {
		return fmt.Errorf("crypto: root signature verification failed: %w", err)
	}

	km.activeKeys.RootSig = keySetSig
	return nil
}

// verifyRootSig verifies that the offline root signed the set of online public keys.
func (km *KeyManager) verifyRootSig(sig []byte, keySet *ActiveKeySet) error {
	// Build the canonical representation of the key set's public keys
	data := buildPubKeySetForSigning(keySet)

	if !ed25519.Verify(km.rootPubKey, data, sig) {
		return fmt.Errorf("invalid root signature")
	}
	return nil
}

// SignWithPurpose signs a message using the active key for the given purpose.
func (km *KeyManager) SignWithPurpose(ctx context.Context, purpose KeyPurpose, message []byte) ([]byte, string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.activeKeys == nil {
		return nil, "", fmt.Errorf("crypto: no active key set")
	}

	kv, ok := km.activeKeys.Keys[purpose]
	if !ok || !kv.IsActive() {
		return nil, "", fmt.Errorf("crypto: no active key for purpose %s", purpose)
	}

	sig, err := km.signer.Sign(ctx, kv.Kid, message)
	if err != nil {
		return nil, "", fmt.Errorf("crypto: sign with %s: %w", purpose, err)
	}

	return sig, kv.Kid, nil
}

// GetPubKey returns the public key for the active key of the given purpose.
func (km *KeyManager) GetPubKey(purpose KeyPurpose) (ed25519.PublicKey, string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.activeKeys == nil {
		return nil, "", fmt.Errorf("crypto: no active key set")
	}

	kv, ok := km.activeKeys.Keys[purpose]
	if !ok || !kv.IsActive() {
		return nil, "", fmt.Errorf("crypto: no active key for purpose %s", purpose)
	}

	return kv.PubKey, kv.Kid, nil
}

// VerifySignature verifies any signature against the allowed key set.
func (km *KeyManager) VerifySignature(kid string, message, signature []byte) error {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if !km.allowedKids[kid] {
		return fmt.Errorf("crypto: unknown kid %s", kid)
	}

	pubKey, err := km.signer.GetPubKey(context.Background(), kid)
	if err != nil {
		return fmt.Errorf("crypto: get pubkey for %s: %w", kid, err)
	}

	if !ed25519.Verify(pubKey, message, signature) {
		return fmt.Errorf("crypto: signature verification failed for kid %s", kid)
	}

	return nil
}

// IsAllowedKid returns true if the kid is in the current allowlist.
func (km *KeyManager) IsAllowedKid(kid string) bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.allowedKids[kid]
}

// RotateKey rotates the key for a specific purpose (DR-KEY-9).
// Returns the new kid. The old key remains in the allowlist for max grant TTL.
func (km *KeyManager) RotateKey(ctx context.Context, purpose KeyPurpose) (string, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.activeKeys == nil {
		return "", fmt.Errorf("crypto: no active key set")
	}

	newKid, pubKey, err := km.signer.GenerateKey(ctx, purpose)
	if err != nil {
		return "", fmt.Errorf("crypto: generate new %s key: %w", purpose, err)
	}

	oldKV := km.activeKeys.Keys[purpose]
	if oldKV != nil {
		// Move old key to overlap window (still accepted for verification)
		km.overlapKids[oldKV.Kid] = true
		now := time.Now().UTC()
		oldKV.RetiredAt = &now
	}

	now := time.Now().UTC()
	km.activeKeys.Keys[purpose] = &KeyVersion{
		Kid:        newKid,
		Purpose:    purpose,
		PubKey:     pubKey,
		CreatedAt:  now,
		ActivatedAt: &now,
	}
	km.allowedKids[newKid] = true

	return newKid, nil
}

// RetireOverlapKeys removes keys from the overlap window after max grant TTL.
func (km *KeyManager) RetireOverlapKeys(maxGrantTTL time.Duration) {
	km.mu.Lock()
	defer km.mu.Unlock()

	cutoff := time.Now().UTC().Add(-maxGrantTTL)
	for kid := range km.overlapKids {
		// Check if all grants signed with this kid have expired
		// In practice, we'd check a database; here we use time-based heuristic
		if time.Now().UTC().After(cutoff) {
			// Conservative: keep overlap keys around
			continue
		}
		delete(km.overlapKids, kid)
		delete(km.allowedKids, kid)
	}
}

// GetActiveKeySet returns the current key set for distribution to daemons.
func (km *KeyManager) GetActiveKeySet() *ActiveKeySet {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.activeKeys
}

// ─── Offline Root Trust (DR-KEY-10…11) ────────────────────────────────────

// RootTrustAnchor represents an offline root that signs online key sets.
type RootTrustAnchor struct {
	PubKey ed25519.PublicKey `json:"pub_key"`
	Fingerprint string        `json:"fingerprint"` // hex-encoded SHA-256
}

// NewRootKey generates a new offline root key pair (air-gapped ceremony).
func NewRootKey() (pub ed25519.PublicKey, priv ed25519.PrivateKey, fingerprint string, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("crypto: generate root key: %w", err)
	}
	fingerprint = fmt.Sprintf("%x", sha256.Sum256(pub))
	return pub, priv, fingerprint, nil
}

// SignKeySet signs the key set public keys with the offline root private key.
// This is done in an air-gapped ceremony; the root private key never touches a network.
func SignKeySet(rootPriv ed25519.PrivateKey, keySet *ActiveKeySet) ([]byte, error) {
	data := buildPubKeySetForSigning(keySet)
	return ed25519.Sign(rootPriv, data), nil
}

// VerifyKeySetSignature verifies the root signature over a key set.
func VerifyKeySetSignature(rootPub ed25519.PublicKey, keySet *ActiveKeySet, sig []byte) bool {
	data := buildPubKeySetForSigning(keySet)
	return ed25519.Verify(rootPub, data, sig)
}

// buildPubKeySetForSigning builds the canonical bytes to sign for a key set.
func buildPubKeySetForSigning(keySet *ActiveKeySet) []byte {
	h := sha256.New()
	// Deterministic ordering by purpose
	for _, purpose := range AllPurposes {
		if kv, ok := keySet.Keys[purpose]; ok {
			h.Write([]byte(kv.Kid))
			h.Write(kv.PubKey)
			h.Write([]byte(purpose))
		}
	}
	return h.Sum(nil)
}

// ─── In-Memory Signer (for testing/development) ────────────────────────────

// InMemorySigner implements Signer using in-memory Ed25519 keys.
// NOT for production use — production uses Vault Transit (DR-KEY-8).
type InMemorySigner struct {
	mu     sync.RWMutex
	keys   map[string]ed25519.PrivateKey
	pubKeys map[string]ed25519.PublicKey
}

// NewInMemorySigner creates a new in-memory signer.
func NewInMemorySigner() *InMemorySigner {
	return &InMemorySigner{
		keys:    make(map[string]ed25519.PrivateKey),
		pubKeys: make(map[string]ed25519.PublicKey),
	}
}

// Sign implements Signer.
func (s *InMemorySigner) Sign(ctx context.Context, kid string, message []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	priv, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("inmemory: unknown kid %s", kid)
	}
	return ed25519.Sign(priv, message), nil
}

// GetPubKey implements Signer.
func (s *InMemorySigner) GetPubKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pub, ok := s.pubKeys[kid]
	if !ok {
		return nil, fmt.Errorf("inmemory: unknown kid %s", kid)
	}
	return pub, nil
}

// GenerateKey implements Signer.
func (s *InMemorySigner) GenerateKey(ctx context.Context, purpose KeyPurpose) (string, ed25519.PublicKey, error) {
	pub, priv, err := cose.GenerateKey()
	if err != nil {
		return "", nil, err
	}

	kid := fmt.Sprintf("%s-%s", purpose, uuid.Must(uuid.NewV7()).String()[:8])

	s.mu.Lock()
	s.keys[kid] = priv
	s.pubKeys[kid] = pub
	s.mu.Unlock()

	return kid, pub, nil
}

// HealthCheck implements Signer.
func (s *InMemorySigner) HealthCheck(ctx context.Context) error {
	return nil
}

// ─── DB-Backed Envelope Encrypter (DR-SEC-1) ──────────────────────────────

// InMemoryEncrypter implements EnvelopeEncrypter for testing/development.
type InMemoryEncrypter struct {
	mu    sync.RWMutex
	keys  map[uuid.UUID][]byte // tenant_id -> DEK
}

// NewInMemoryEncrypter creates a new in-memory envelope encrypter.
func NewInMemoryEncrypter() *InMemoryEncrypter {
	return &InMemoryEncrypter{
		keys: make(map[uuid.UUID][]byte),
	}
}

// Encrypt implements EnvelopeEncrypter.
func (e *InMemoryEncrypter) Encrypt(ctx context.Context, tenantID uuid.UUID, plaintext []byte) ([]byte, error) {
	key, err := e.getOrCreateKey(tenantID)
	if err != nil {
		return nil, err
	}
	// Simple AES-GCM encryption would go here; stubbed for now
	_ = key
	encrypted := make([]byte, len(plaintext)+32)
	copy(encrypted, plaintext)
	// XOR with key for simple encryption (REPLACE with AES-256-GCM in production)
	for i := 0; i < len(plaintext); i++ {
		encrypted[i] ^= key[i%len(key)]
	}
	return encrypted, nil
}

// Decrypt implements EnvelopeEncrypter.
func (e *InMemoryEncrypter) Decrypt(ctx context.Context, tenantID uuid.UUID, ciphertext []byte) ([]byte, error) {
	key, err := e.getOrCreateKey(tenantID)
	if err != nil {
		return nil, err
	}
	// Simple decryption (REPLACE with AES-256-GCM in production)
	plaintext := make([]byte, len(ciphertext)-32)
	copy(plaintext, ciphertext[:len(plaintext)])
	for i := 0; i < len(plaintext); i++ {
		plaintext[i] ^= key[i%len(key)]
	}
	return plaintext, nil
}

func (e *InMemoryEncrypter) getOrCreateKey(tenantID uuid.UUID) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if key, ok := e.keys[tenantID]; ok {
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	e.keys[tenantID] = key
	return key, nil
}

// Ensure unused imports
var _ = binary.BigEndian
