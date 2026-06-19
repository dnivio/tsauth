# TSAuth / Dnivio — Internal Security Audit

**Date:** 2026-06-19
**Scope:** Implementation review of the Go Approval Service, the enforcement daemon, the SQL schema/migrations, and the Android approver app — measured against `ENGINEERING.md` v2.1.
**Type:** Adversarial (white-box) code review, with emphasis on cryptography, authorization, replay/binding, multi-tenant isolation, and concurrency/timing.

> **This document audits the *code as it exists in the repository*, not the design.** The design in `ENGINEERING.md` is sound. The implementation is, at this stage, a **non-enforcing skeleton**: most security-critical controls are placeholders, mocks, broken, or unwired.

---

## Top-line verdict

**Do not deploy or present this as functioning security tooling yet.** The full login/authentication and approval **enforcement flow is not implemented end-to-end.** Critically, the enforcement daemon's authorization decision is currently hardcoded to *allow*, and grant/approval signatures are never verified. A deployment in this state would *appear* to enforce biometric step-up while silently allowing all access — which is more dangerous than shipping nothing, because it manufactures false confidence.

The design is strong and several components are well-built (see [What's done well](#whats-done-well)). The gap is implementation completeness plus a set of real bugs in the parts that are "done."

### Coverage

Reviewed in depth: `contracts/` (envelope, COSE, identity), `service/internal/{crypto,auth,config,enforcement,policy,revocation,enrollment,audit,ratelimit,messaging}`, `service/cmd/approval-service`, `service/migrations`, the full `daemon/`, and the Android approver's `KeyManager`, `RequestVerifier`, `ApprovalClient`, manifest, and network config.

Not exhaustively reviewed: `service/internal/{api,db,version,observability}`, Android `CoseVerifier`/`EnrollmentManager`/`ApprovalActivity`/FCM/PoP services, and `sdk/go/client.go`. These do not change the conclusions below.

### Severity summary

| Sev | Count | Theme |
|---|---|---|
| Critical | 10 | Authorization bypass; placeholder crypto; no signature/attestation verification; broken tenant isolation; SQL injection |
| High | 12 | Not buildable daemon; firewall never installed; runtime panics; RBAC race + stale auth; audit not tamper-evident; no transport security; OIDC absent |
| Medium | 10 | Canonicalization without domain separation; policy selector gaps; non-atomic Android counter; cookie/path bugs; DoS bounds unenforced |

---

## Critical

### C1 — The enforcement daemon approves everything
`daemon/cmd/dnv-daemon/main.go:168-180` — `requestApproval` is wired into SSH, the TCP proxy, *and* the HTTP path, and unconditionally returns `Approved: true` with a freshly minted JTI. It never contacts the Approval Service, never waits for a biometric, never checks a grant. `PreAuthorize` (`main.go:86-89`) also always returns `true`. The gate is wired open.

### C2 — The daemon never verifies an Access Grant Token
No call to `VerifyAccessGrantToken`/`Verify1` exists anywhere under `daemon/`. `grants/cache.go` `Store/Check/Consume` operate on an already-decoded `AGTPayload` and never check the COSE signature, signing key, epoch, or binding.

### C3 — The service never verifies approval-response signatures
`contracts.VerifyApprovalResponse` (`contracts/envelope.go:203`) is **never called**. `enforcement/engine.go:227 ProcessApproval` records `response_sig` and checks a counter, but never validates the biometric signature over the request. The core proof of the product is never checked.

### C4 — Single-use grant consumption is dead code
The atomic `consume_grant` SQL function (`migrations/001_initial_schema.up.sql:486`) is never called from Go. Grants are never consumed → infinitely replayable even if they were verified. Session-kill / `active_sessions` paths are likewise unwired.

### C5 — Production uses placeholder crypto only; root of trust is fictional
`service/cmd/approval-service/main.go:192` always constructs `crypto.NewInMemorySigner()` (no Vault path). `initCrypto` (`main.go:196-221`) generates a **new "offline root" key on every boot**, discards the private key, and sets `rootSig := []byte{}` — `SetRootSignature` is never called. Signing keys are ephemeral and unanchored (DR-KEY-10/11 non-functional).

### C6 — "Envelope encryption" is repeating-key XOR
`crypto/keymanager.go:436-465` — `InMemoryEncrypter.Encrypt` XORs plaintext against `key[i % 32]` and appends 32 zero bytes posing as a GCM tag. It is the only `EnvelopeEncrypter` implementation. Anything "encrypted at rest" with it is trivially recoverable.

### C7 — Hardware attestation is a no-op trusting a self-asserted field
`enrollment/oidc.go:205-225 verifyAttestation` validates nothing — it only checks that the client-supplied `SecurityLevel` string is `TEE`/`STRONGBOX`. No cert-chain validation, challenge binding, key-in-hardware proof, or boot/patch checks. Combined with `mintGrant` hardcoding `DeviceSecurityLevel: STRONGBOX` (`enforcement/engine.go:373`), the device-security-level guarantee (DR-KEY-6) is end-to-end fictional.

### C8 — Grants carry an empty scope binding
`mintGrant` (`enforcement/engine.go:366-391`) never copies the request `Binding` into the AGT and hardcodes `AuthzEpoch: 1`, `SrcNodeKeyEpoch: 0`, `ApproverDeviceID: uuid.Nil`. The scope-specific binding (request_nonce / connection_id / session_id — the anti-replay mechanism, C-04/05/06) is absent from every grant.

### C9 — Multi-tenant RLS provides no isolation as wired
`migrations/001_initial_schema.up.sql:373-429` enables RLS but never `FORCE ROW LEVEL SECURITY` and creates no restricted application role. The documented DB user is the table owner (`config.go:144`), and **owners bypass non-forced RLS**. Separately, no Go code issues `SET LOCAL app.current_tenant_id`, so the predicate would be `tenant_id = NULL` if it did apply. Tenant isolation rests entirely on hand-written `WHERE tenant_id = $1` clauses plus an auth layer that is not implemented.

### C10 — SQL injection in the delivery notifier
`messaging/outbox.go:250-252` — `ds.db.ExecContext(ctx, fmt.Sprintf("NOTIFY %s", key))` where `key` embeds the free-form `consumer` string. Classic injection sink (and broken regardless, since the value isn't a valid channel identifier). Use `pg_notify($1, $2)`.

---

## High

### H1 — The daemon is not buildable
`daemon/` has **no `go.mod`** and is absent from `go.work`; its sources import `github.com/dnivio/daemon/...`, which resolves to nothing. The "daemon binary" cannot be produced from this tree.

### H2 — Firewall backend-isolation is never installed (and never fails closed)
`daemon/internal/firewall/manager.go:225-227` — `cmd.Stdin = exec.Command("echo", nftScript).Stdout` wires a never-started command's `io.Writer` field into the `io.Reader` `Stdin`; `nft` receives nothing. The "OS-level ingress invariant" (DR-ENF-2) — the assumption the backend is unreachable except through Dnivio — is never enforced, so the backend stays directly reachable. `verify()` (`:296-313`) discards the "rules absent" error and takes no fail-closed action (DR-ENF-5 absent). `ProbeBackendReachability` returns "safe" on any error (false negative).

### H3 — Signing path panics at runtime
`main.go:246 / :262` call `contracts.NewRequestEnvelope(nil, …)` / `NewAccessGrantToken(nil, …)`, reaching `ed25519.Sign(nil, …)`, which panics. Wherever the engine is invoked it crashes. (Currently the engine is `_ = engine` and the gRPC handlers are commented out — the running service exposes only `/health` and `/v1/status`.)

### H4 — RBAC role cache: data race + cross-tenant staleness
`auth/rbac.go:255-282` reads/writes the plain `userRoles` map with no mutex while `AssignRole`/`RemoveRole` mutate it → Go's fatal concurrent-map-write panic (DoS) under concurrent handlers. The cache is keyed by **`userID` only, ignoring `tenantID`**, and is never TTL- or cross-replica-invalidated → revoked privileges persist; one tenant's roles can be returned in another tenant's context.

### H5 — Broken IDOR check for policies
`auth/rbac.go:239-245 CheckObjectOwnership("policy")` ignores `objectID` and only checks that *some* policy exists in the tenant — any policy id passes the ownership gate.

### H6 — SSH authorization is locally forgeable and fails open
`ssh/enforcer.go` — the daemon's Unix-socket `handleRequest` (`:251`) performs no peer-credential check; any local process can connect and obtain `ALLOW`. `AuthorizedKeysHelper.Execute` (`:162-189`) returns the key for **any** response that isn't exactly `"DENY"` (fail-open). The `fmt.Sscanf("ACCT,%s,%s", …)` parse is also wrong (`%s` is greedy to whitespace).

### H7 — Audit chain is not tamper-evident and corrupts itself
Row hash (`migrations/...up.sql:572`) is `SHA-256(prev_hash || seq || event_type || epoch)` — it **excludes the payload and all detail columns** (written in a second `UPDATE` in `audit/chain.go:137`). `VerifyChain` (`chain.go:298`) never recomputes row hashes, only checks linkage. `exportCheckpoint` (`chain.go:283-289`) inserts an `audit_events` row with `prev_hash='\x00', row_hash='\x00'`, breaking the chain it should anchor; checkpoints aren't exported to immutable storage and are signed with the ephemeral key from C5.

### H8 — Revocation has no payload and races on sequence
`revocation/manager.go:116` queues outbox messages with `Payload: nil` — daemons can't learn what was revoked. `MAX(seq)+1` allocation in `IssueRevocation`/`issueRevocationInTx` (`:74, :332`) and in `messaging/outbox.go:42-45 WriteTx` is a read-modify-write race that collides sequence numbers and breaks ordered delivery.

### H9 — Daemon grant cache: replay across restart / re-delivery
`grants/cache.go:270` generates the persistence AEAD key randomly per process. After restart, the `.consumed` log is undecryptable (single-use state lost / cache init error). `Consume` checks only the in-memory `entry.Consumed`; the loaded `consumedJTIs` set is never consulted, so re-delivering a consumed single-use grant resets it → replay.

### H10 — No transport security on the service
`main.go:82, 96-99` — gRPC has no mTLS (`grpc.Creds`) and HTTP uses plaintext `ListenAndServe`, despite the mTLS-daemon-bootstrap design. `config.go:148` defaults Postgres `sslmode=require`, which encrypts but does not verify the server certificate (MITM-able); use `verify-full`.

### H11 — OIDC authentication is not implemented (the login flow)
`enrollment/oidc.go` has ticket plumbing only — no ID-token verification: no JWKS, no signature/`iss`/`aud`/`exp`/`nonce`/PKCE validation (RFC 9700). `ValidateIssuer` checks an allowlist string. The user login/authentication flow is effectively absent.

### H12 — Android verifier cannot verify real signatures (algorithm mismatch)
`RequestVerifier.kt:92` accepts `alg` ∈ {EdDSA(-8), ES256(-7)} but `verifySignature` (`:184`) always uses `SHA256withECDSA`. The service signs with **Ed25519**. The COSE structures also differ (Go map-struct protected header vs Android RFC-9052 `protectedRaw`), so cross-implementation verification cannot succeed.

---

## Medium

- **M1 — Signed payloads built by raw concatenation (no domain separation).** `SignApprovalResponse`/`VerifyApprovalResponse` (`contracts/envelope.go:183-219`) concatenate variable-length fields with no length prefixes; `ComputeDisplayDigest` (`:133`), `buildPubKeySetForSigning` (`crypto/keymanager.go:343`), `buildBundleForSigning` (`policy/engine.go:610`) share the issue. Use length-delimited or canonical CBOR everywhere signed.
- **M2 — Policy selector gaps.** `policy/engine.go:237-269 subjectMatches` ignores `Groups`/`DeviceTags` (a group-scoped DENY silently never fires). `resourceMatches` (`:271-306`) early-returns on the first non-empty dimension, breaking OR-within-selector semantics.
- **M3 — Panic / non-existent-function crashers.** `policy/engine.go:338` and `enforcement/engine.go:411` `uuid.MustParse` stored strings (non-UUID → panic). The schema's `DEFAULT uuid_generate_v7()` is not provided by `uuid-ossp`; the migration will not run as written.
- **M4 — Policy load trusts the DB.** `loadActiveBundle` (`policy/engine.go:359`) never verifies bundle `signature`/`prev_hash`; `PublishPolicy` enforces no separation-of-duties.
- **M5 — Android counter is non-atomic and plaintext.** `KeyManager.kt:228` read-modify-write with async `apply()` (race → counter reuse); stored in `MODE_PRIVATE` SharedPreferences, not `EncryptedSharedPreferences` as documented → rollback/replay on a rooted device.
- **M6 — StrongBox unreachable.** Both Android keys use `setIsStrongBoxBacked(false)` (`KeyManager.kt:85, 114`); no device can satisfy a StrongBox requirement.
- **M7 — `__Host-` cookies use a non-root path.** `interstitial/handler.go:131-139, 277-285` — the `__Host-` prefix requires `Path=/`; compliant browsers reject these cookies → interstitial breaks.
- **M8 — TCP proxy DoS / dead pre-approval buffer.** `tcpproxy/proxy.go` — held connections have no hold deadline (DoS by exhausting `maxPendingConns`); `heldConnection.Buffered` is never allocated and `Read` never called, so the byte/memory bounds (DR-CAP-2) are unenforced.
- **M9 — Rate limiting unwired and racy.** The `ratelimit` package isn't referenced from `main.go`; `InMemoryStore.Allow` (`:163`) mutates a map without a lock. Approval-bombing is unbounded as shipped.
- **M10 — Daemon HTTP path leaks backend / double-binds port / ignores config.** `main.go:124-131` grant-cache key (`Host/Method/Path`) can never match a stored key; `forwardToBackend` (`:182-186`) 307-redirects the client browser to plaintext `http://backend:port`; the TCP proxy and HTTPS server both bind `:ProxyPort`; `loadDaemonConfig` (`:228`) ignores the config file (`_ = data`).

---

## Timing & side-channel analysis

No exploitable constant-time-comparison flaw was found: secret-bearing comparisons correctly use `subtle.ConstantTimeCompare` (`enrollment/oidc.go:130`, `interstitial/handler.go:227, 258`), `MessageDigest.isEqual` (Android), and `ed25519.Verify` (internally constant-time). The display-digest/ticket comparisons aren't secret oracles (signed payloads / hashed high-entropy tokens).

The real side-channel-adjacent risks are **concurrency-correctness** issues:
- **Device-counter TOCTOU** — `enforcement/engine.go:268-308` reads the counter without `FOR UPDATE`; concurrent approvals from one device both pass the `<=` check (anti-clone counter, DR-SIG-6, bypassable under concurrency).
- **Sequence-number races** — `MAX(seq)+1` in revocation and outbox (see H8).
- **Unsynchronized maps** — the RBAC cache (H4) and `InMemoryStore` (M9) are remotely-triggerable fatal crashes (DoS) under Go's race detector / concurrent load.

`IsLowS` (`contracts/cose/cose.go:220`) is a fragile hand-rolled DER parser (no `SEQUENCE`-tag or long-form length validation); malformed input returns `false` (safe) but it should be replaced with a vetted decoder.

---

## What's done well

- **Android key policy** (`KeyManager.kt`): `approval_auth` with `setUserAuthenticationRequired(true)`, per-operation timeout `0`, `AUTH_BIOMETRIC_STRONG`, `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)` for `device_auth`, and the `CryptoObject` sign pattern — the correct spec.
- **SQL data model**: tenant-scoped composite FKs, the `validate_grant_ttl` trigger, optimistic `transition_approval_request`, advisory-lock audit insertion, atomic `consume_grant` (even though unused).
- **Interstitial** security headers/CSP, constant-shape status responses, and separate poll/redeem capabilities (modulo the `__Host-`/path bug).
- **Contracts** type model (typed `ResourceID` vs untrusted `DisplayLabel`; verify-before-render on Android) and **enrollment ticket** hashing.
- `grants/cache.go` AEAD persistence uses real AES-GCM with random nonces (the weakness is the ephemeral key, H9).

---

## Recommendations (priority order)

1. **Gate the build against placeholders.** Remove `InMemorySigner` / `InMemoryEncrypter` / `NoOpStore` from production builds; fail hard if KMS (Vault), real attestation, and TLS/mTLS aren't configured. Add `daemon` to `go.work` with a `go.mod`; add a CI gate: `go build ./...`, `go vet`, `go test ./... -race`.
2. **Implement the enforcement + login flow** (currently missing): OIDC ID-token verification (H11); daemon→service approval round-trip (C1); AGT signature + epoch + binding verification (C2, C8); call `consume_grant` (C4); verify `ApprovalResponse` signatures (C3); real attestation-chain validation (C7).
3. **Fix tenant isolation**: `FORCE ROW LEVEL SECURITY` + a dedicated restricted DB role + per-request `SET LOCAL app.current_tenant_id` (C9); replace `NOTIFY` string interpolation with `pg_notify($1, $2)` (C10); fix `uuid_generate_v7` (M3).
4. **Fix firewall install + make `verify()` fail closed** (H2) — the ingress invariant the whole model depends on.
5. **Replace raw-concat signed payloads** with length-delimited / CBOR; align Go (Ed25519) and Android (currently ECDSA-only) COSE (M1, H12).
6. **Harden audit integrity**: include payload + all detail columns in the row hash; recompute hashes in `VerifyChain`; export checkpoints to immutable storage without breaking the chain (H7).
7. Run with `-race` and add `FOR UPDATE` to the device-counter read (timing/concurrency section).

---

*This audit reflects the repository state on 2026-06-19. Findings reference `file:line` at that revision; line numbers may drift as the code changes.*
