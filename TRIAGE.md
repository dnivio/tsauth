# Triage Report — SECURITY_AUDIT.md

**Date:** 2026-06-20
**Source:** `SECURITY_AUDIT.md` (2026-06-19), 44 findings against ENGINEERING.md v2.1

---

## Critical (10)

### C1 — Enforcement daemon approves everything
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `daemon/cmd/dnv-daemon/main.go` | 168–180 | `requestApproval` returns `Approved: true` unconditionally | Wire real gRPC call to Approval Service |
| `daemon/cmd/dnv-daemon/main.go` | 86–89 | `PreAuthorize` always returns true | Implement Tailscale ACL check |
| `daemon/cmd/dnv-daemon/main.go` | 124–131 | HTTP grant-cache key format mismatch with stored keys | Align key formats |

### C2 — Daemon never verifies AGT signatures
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `daemon/internal/grants/cache.go` | 139–159 | `Check` uses pre-decoded payload, never verified | Add `VerifyAndStore(rawAGT)` that calls `contracts.VerifyAccessGrantToken` before storing |

### C3 — Service never verifies approval-response signatures
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/internal/enforcement/engine.go` | 207–342 | `ProcessApproval` never calls `contracts.VerifyApprovalResponse` | Call `VerifyApprovalResponse` before accepting decision |

### C4 — Single-use grant consumption dead code
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/migrations/001_initial_schema.up.sql` | 486–521 | `consume_grant()` exists but never called from Go | Add gRPC `ConsumeGrant` endpoint; wire daemon to call it |

### C5 — Production uses placeholder crypto
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/cmd/approval-service/main.go` | 192 | Always `crypto.NewInMemorySigner()` | Gate: fail hard if Vault not configured |
| `service/cmd/approval-service/main.go` | 196 | New root key generated every boot | Load from sealed config |
| `service/cmd/approval-service/main.go` | 216 | `rootSig := []byte{}`; `SetRootSignature` never called | Load root signature from offline ceremony artifact |

### C6 — "Envelope encryption" is repeating-key XOR
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/internal/crypto/keymanager.go` | 436–465 | XOR "encryption" with zero-byte fake tag | Replace with AES-256-GCM |

### C7 — Hardware attestation is a no-op
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/internal/enrollment/oidc.go` | 205–225 | Only checks self-asserted `SecurityLevel` string | Implement full cert-chain verification |
| `service/internal/enforcement/engine.go` | 373 | Hardcodes `DeviceSecurityLevel: STRONGBOX` | Pull from device record |

### C8 — Grants carry empty scope binding
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/internal/enforcement/engine.go` | 366–391 | `mintGrant` never copies `Binding`, hardcodes `SrcNodeKeyEpoch: 0`, `ApproverDeviceID: uuid.Nil`, `AuthzEpoch: 1` | Populate from request/DB state |

### C9 — Multi-tenant RLS provides no isolation
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/migrations/001_initial_schema.up.sql` | 373–429 | RLS enabled but not FORCE'd; table owner bypasses | Add `FORCE ROW LEVEL SECURITY`; create restricted app role |
| `service/internal/config/config.go` | 144 | DB user is table owner | Create non-owner `dnivio_app` role |
| All Go code | — | No `SET LOCAL app.current_tenant_id` | Add gRPC interceptor |

### C10 — SQL injection in NOTIFY
| File | Lines | Behavior | Fix |
|---|---|---|---|
| `service/internal/messaging/outbox.go` | 250–252 | `fmt.Sprintf("NOTIFY %s", key)` | Use `SELECT pg_notify($1, $2)` |

---

## High (12)

### H1 — Daemon not buildable
- `daemon/` has no `go.mod`, absent from `go.work`
- Imports `github.com/dnivio/daemon/...` → resolves to nothing

### H2 — Firewall never installed, never fails closed
- `firewall/manager.go:225-227`: Stdin wiring is broken
- `verify()` (:296-313) discards "rules absent" error
- `ProbeBackendReachability` returns "safe" on any error

### H3 — Signing path panics
- `main.go:246/:262`: `contracts.NewRequestEnvelope(nil, ...)` → panics on `ed25519.Sign(nil, ...)`
- Currently `_ = engine`, handlers commented out — crashes when wired

### H4 — RBAC cache: data race + cross-tenant staleness
- `auth/rbac.go:255-282`: `userRoles` map with no mutex; keyed by `userID` only (ignores `tenantID`); no TTL/cross-replica invalidation

### H5 — Broken IDOR check for policies
- `auth/rbac.go:239-245`: `CheckObjectOwnership("policy")` ignores `objectID`

### H6 — SSH authorization locally forgeable + fails open
- `ssh/enforcer.go:251`: No peer-credential check on Unix socket
- `ssh/enforcer.go:162-189`: `AuthorizedKeysHelper` returns key for any response ≠ "DENY"
- `ssh/enforcer.go:264`: `fmt.Sscanf` greedy parse bug

### H7 — Audit chain not tamper-evident, corrupts itself
- Row hash excludes payload/detail columns
- `VerifyChain` doesn't recompute row hashes
- `exportCheckpoint` inserts `prev_hash='\x00', row_hash='\x00'`, breaking chain

### H8 — Revocation: nil payload, sequence races
- `revocation/manager.go:116`: `Payload: nil`
- `MAX(seq)+1` read-modify-write race in revocation + outbox

### H9 — Daemon grant cache: replay across restart
- `grants/cache.go:270`: AEAD key random per process → undecryptable after restart
- `Consume` doesn't check loaded `consumedJTIs`

### H10 — No transport security
- gRPC has no mTLS; HTTP uses plaintext `ListenAndServe`
- Postgres `sslmode=require` (no cert verification)

### H11 — OIDC authentication not implemented
- Ticket plumbing only; no ID-token verification (JWKS, sig, claims)

### H12 — Android verifier can't verify Ed25519
- `RequestVerifier.kt:184`: always `SHA256withECDSA`, service signs Ed25519

---

## Medium (10)

### M1 — Raw concatenation without domain separation
- `SignApprovalResponse`, `ComputeDisplayDigest`, `buildPubKeySetForSigning`, `buildBundleForSigning` all concatenate variable-length fields

### M2 — Policy selector gaps
- `subjectMatches` ignores Groups/DeviceTags
- `resourceMatches` early-returns breaking OR-within-selector

### M3 — Panic crashers
- `uuid.MustParse` on stored strings → panic for non-UUIDs
- `DEFAULT uuid_generate_v7()` not provided by `uuid-ossp`

### M4 — Policy load trusts DB
- `loadActiveBundle` never verifies bundle `signature`/`prev_hash`

### M5 — Android counter non-atomic + plaintext
- `MODE_PRIVATE` + `apply()` (async) → race + rollback on rooted device

### M6 — StrongBox unreachable
- Both keys use `setIsStrongBoxBacked(false)`

### M7 — `__Host-` cookie path violation
- `__Host-` prefix requires `Path=/`; uses narrow path → broken in compliant browsers

### M8 — TCP proxy DoS bounds unenforced
- `heldConnection.Buffered` never allocated
- No hold deadline

### M9 — Rate limiting unwired + racy
- `ratelimit` package not imported in `main.go`
- `InMemoryStore.Allow` mutates map without lock

### M10 — Daemon HTTP path bugs
- Grant-cache key mismatch; 307-redirect leaks backend; port conflict; config ignored

---

## Timing & Concurrency

- **TC1** (engine.go:270): Device counter read without `FOR UPDATE` → concurrent approvals bypass counter
- **TC2** (revocation:74): `MAX(seq)+1` race
- **TC3** (outbox:42): `MAX(seq)+1` race
- **TC4** (rbac:255): Unsynchronized `userRoles` map
- **TC5** (ratelimit:163): Unsynchronized `InMemoryStore.buckets`

---

## Implementation Priority

| Priority | Group | Findings | Est. effort |
|---|---|---|---|
| P0 | Gate build against placeholders | C5, C6, H1 | Hours |
| P1 | Core crypto verification | C2, C3, C8, H3 | Days |
| P2 | Enforcement flow | C1, C4 | Days |
| P3 | Tenant isolation | C9, C10 | Hours |
| P4 | Infra security | H2, H7, H9, H10 | Days |
| P5 | Correctness/races | H4, H5, H6, H8, TC1-5, M9 | Days |
| P6 | Payload canonicalization | M1, M7 | Hours |
| P7 | Feature completeness | C7, H11, H12, M2-M6, M8, M10 | Weeks |
