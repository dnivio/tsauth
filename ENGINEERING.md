# Dnivio — Engineering Specification

**Project:** Dnivio Biometric Access Verification for Tailscale
**Spec version:** v2.1 (supersedes v2.0; adversarial re-review decisions applied)
**Status:** **Specification — NOT implementation-ready code.** This document is the normative build authority; no source, tests, or release artifacts exist yet (see C-01 disposition in §23).
**Inputs:** [`design.md`](./design.md) (client requirements), [`ADVERSARIAL_REVIEW.md`](./ADVERSARIAL_REVIEW.md) (review), [`REVIEW_RESPONSE.md`](./REVIEW_RESPONSE.md) (finding→resolution map).

---

## 0. Authority, hierarchy, and how to read this

**Source-of-truth hierarchy (resolves M-01):**
1. **`ENGINEERING.md` (this document) is the single normative specification.** Where it conflicts with `design.md`, this document wins, *except* it never reduces a `design.md` security requirement.
2. `design.md` is the client's requirements input. Its delivery phases control sequencing only and do **not** make any listed capability optional. Every capability in `design.md` is required for GA.
3. `ADVERSARIAL_REVIEW.md` findings are mandatory acceptance criteria; `REVIEW_RESPONSE.md` maps each finding to its resolution here.

**Normative language:** MUST / MUST NOT / SHALL / SHOULD / MAY per RFC 2119/8174. A sentence with no keyword is descriptive, not a requirement.

**Requirement IDs (resolves M-02):** Normative requirements carry stable IDs `DR-<area>-<n>` (e.g. `DR-ENF-3`). The traceability database (`docs/traceability.csv`, built in P0) maps every `DR-*` → design clause → review finding → code module → unit/integration/E2E/security test → operational control → release-evidence artifact. A requirement is "done" only when every column has a green, linked artifact. This document defines the requirements and their IDs; the CSV is the living evidence ledger.

**How to read:** §3–§6 are the cross-cutting models every component depends on — read them first and treat their identifiers as frozen vocabulary. §7–§21 are component specs. §22 is the mandatory release-gate matrix. §23 is the delivery plan. §24 records final product decisions; it contains no unresolved scope choices.

---

## 1. Terminology corrections vs v1.0

v1.0 used several terms loosely; v2.1 fixes them and they are used consistently throughout:

- **Initiating principal** — the typed identity of the source of an access attempt (§3.2). Never assumed to be a human (resolves H-26).
- **Protected resource** — a typed, registered `(tenant, protected_node, service, port, transport, deployment_mode)` tuple (§3.3), not a `host:port` string (resolves M-04).
- **Enforcement mode** — exactly one of the supported modes (§7.4) bound to a protected resource. There is exactly one authoritative enforcement layer per listener (resolves H-01).
- **Grant** — a service-signed Access Grant Token (AGT) **plus** the daemon-side authorization record it produces; both carry the full binding set (§9).
- **Revocation freshness bound** — the maximum tolerated staleness of revocation state at an enforcement point; exceeding it fails closed (§13). Replaces the inaccurate word "immediate."

---

## 2. Glossary

| Term | Definition |
|---|---|
| Tenant | An isolated customer/organization. `tenant_id` (UUIDv7) scopes every identity, record, index, and decision (resolves C-13). |
| Tailnet | A Tailscale network within a tenant. A tenant can own multiple tailnets; `tailnet_id` is recorded explicitly and is unique within the tenant. |
| Protected node | A tailnet machine hosting a protected resource and running the Dnivio enforcement daemon. |
| Enforcement point | The Dnivio daemon's authoritative mediation path for one protected resource + mode. |
| Approver device | A user's enrolled mobile device holding two attested keys (§8.2); the biometric second factor. |
| AGT | Access Grant Token: COSE_Sign1 (Ed25519) authorization with the full binding set (§9.3). |
| Policy bundle | Signed, versioned, tenant-scoped policy set distributed by the Service (§12). |
| Outbox/Inbox | Transactional durable-delivery tables backing all security-critical messaging (§11.5). |
| WhoIs | Tailscale source→identity resolution; in Dnivio always passed through the typed principal resolver (§3.2). |

---

## 3. Cross-cutting identity & resource model

This section is frozen vocabulary for the whole spec. (Resolves C-04, C-10, C-13, H-21, H-26, M-04.)

### 3.1 Tenancy (DR-TEN-1…3)

- **DR-TEN-1:** Every identity, request, grant, policy, node, device, revocation, session, and audit row MUST carry `tenant_id`, and every uniqueness/lookup index MUST include it. Single-tenant deployments run with exactly one `tenants` row; the schema and code paths are identical.
- **DR-TEN-2:** Every API call MUST resolve a tenant from the authenticated principal and MUST enforce tenant scoping server-side (Postgres Row-Level Security + application guard). Cross-tenant reads/writes MUST be impossible even with a valid other-tenant credential.
- **DR-TEN-3:** Cross-tenant and IDOR tests (§22.3) are release gates for every object endpoint.

### 3.2 Initiating principal resolution (DR-ID-1…6)

The daemon resolves the source of each attempt to a typed principal before any decision:

```
Principal {
  tenant_id
  tailnet_id
  src_node_id        // Tailscale STABLE node id (not IP)
  src_node_key_epoch // increments on node-key change / re-key
  kind               // HUMAN | TAGGED | SERVICE | SUBNET_ROUTER | APP_CONNECTOR | UNKNOWN
  user               // (oidc_issuer, oidc_subject, user_id) — present only when kind=HUMAN and unique
  node_state         // OK | EXPIRED | DELETED | KEY_CHANGED
  posture_version    // device posture snapshot id, or explicit NONE
}
```

- **DR-ID-1:** Identity MUST be derived from the stable node id + tenant, never from IP alone. IP/port are recorded for audit but are not identity.
- **DR-ID-2:** `WhoIs` results MUST be passed through the resolver. A tagged/service/subnet/app-connector source resolves to a non-HUMAN kind.
- **DR-ID-3 (fail-closed):** If a policy requires a human principal and no unique, current, non-expired human can be established, the decision is **DENY** (resolves H-26).
- **DR-ID-4:** A protected resource MAY define an explicit machine-identity policy permitting a named tagged/service principal; absent that, non-human principals to a protected resource are DENY.
- **DR-ID-5:** `src_node_key_epoch` and `node_state` MUST be revalidated on every grant use; `EXPIRED|DELETED|KEY_CHANGED` invalidates cached grants for that node.
- **DR-ID-6 (authoritative user link):** a Tailscale control-plane user identity MUST NOT be assumed to equal an OIDC identity. The Service maintains a tenant-scoped `identity_links` record binding `(tailnet_id, tailscale_user_id)` to `(oidc_issuer, oidc_subject, user_id)`. The link is created only from a verified Tailscale/headscale inventory adapter plus authenticated OIDC enrollment or administrator-approved reconciliation. Missing, ambiguous, stale, or conflicting links are **DENY**. Link changes increment `authz_epoch`, revoke affected grants, and are audited.

### 3.3 Protected-resource identity (DR-RES-1…3)

```
ResourceID {                 // canonical; the only thing bindings/policy reference
  tenant_id
  protected_node_id
  service_id                 // operator-assigned stable id
  port
  transport                  // TCP | (UDP reserved, §7.3)
  deployment_mode            // HTTP_PROXY | OPAQUE_TCP | TS_SSH | OPENSSH
}
DisplayLabel { name, source_hint }   // untrusted, never used in bindings (resolves M-04, M-05)
```

- **DR-RES-1:** Bindings, policy, grants, and audit MUST reference `ResourceID`, never a display string. Hostnames/aliases/IPv6/case/trailing-dot/IDNA are normalized to `ResourceID` at registration; ambiguity is rejected.
- **DR-RES-2:** A resource is "protected" only if it exists in the protected-resource registry (§12.1) with a supported `deployment_mode`. Marking a resource protected requires passing the backend-isolation probe (§7.5).
- **DR-RES-3:** A protected resource reachable on a transport/mode not covered by its registration MUST be DENY (fail-closed), never fall through to Tailscale ACL allow (resolves C-12, C-03).

### 3.4 Key identities

| Identity | Key(s) | Purpose |
|---|---|---|
| Approver device | `device_auth` (HW, non-exportable, background-capable) + `approval_auth` (HW, `AUTH_BIOMETRIC_STRONG`, per-use) | §8.2 — resolves C-07 |
| Protected node | mTLS client cert (CSR bound to stable node id+tenant) | §14.3 — resolves C-14 |
| Service signers | `request_sig`, `grant_sig`, `policy_sig`, `audit_checkpoint_sig` (separate Ed25519 keys in Vault Transit) | §8.4 |
| Offline product/tenant root | air-gapped Ed25519 root signing online key-sets | §8.5 — resolves H-08 |

---

## 4. Architecture, planes, trust boundaries

### 4.1 Planes

- **Coordination plane (networking):** stock Tailscale or headscale. Dnivio does not fork it (ADR-005).
- **Data plane:** WireGuard, unchanged. Dnivio inserts an OS-enforced ingress chokepoint at protected nodes (§7).
- **Authorization plane (new):** Service + daemon enforcement + approver devices + durable messaging.

### 4.2 Trust boundaries & explicit trust assumptions (resolves H-25)

- **DR-TM-1:** The protected node's daemon is trusted to enforce. A compromised protected node can bypass its own controls and fabricate daemon-reported flow audit. Required mitigations are minimal split privileges, OS-protected node identity/grant-cache keys, service/process isolation, signed packages and updates, enforcement-integrity monitoring, and audit provenance separation. Service-authored approval/grant/revocation history remains distinct from daemon-reported flow events.
- **DR-TM-2:** The Service is trusted for issuance; signing keys live in Vault Transit and never exist in Approval Service memory as private key bytes.
- **DR-TM-3:** The approver device's `approval_auth` key is the root of human-approval trust; its hardware attestation is verified at enrollment and its use requires a fresh strong biometric.
- Boundaries and their auth: daemon↔service (node mTLS + live tailnet identity, §14.3); approver↔service (`device_auth` signed channel + per-approval `approval_auth` signature); browser↔daemon (typed principal resolution, §3.2); service↔Vault (short-lived workload identity, mTLS, least-privilege Transit policy).

---

## 5. Architectural decisions (ADRs)

Retained from v1 unless noted; new/changed ADRs marked.

- **ADR-001 (retained):** Authoritative enforcement is destination/protected-node side.
- **ADR-002 (retained):** Approval Service in Go 1.22+.
- **ADR-003 (REVISED):** Approver uses **two** attested keys — `device_auth` and `approval_auth` (resolves C-07).
- **ADR-004 (REVISED):** Grants are Ed25519 COSE AGTs carrying the **full binding set** including tenant, initiating node, policy version, authz epoch, and scope-specific binding (resolves C-04, C-05, C-06, C-10).
- **ADR-005 (retained):** Policy distributed by the Service, signed/versioned; coordination server not forked.
- **ADR-006 (REVISED):** Transport = reconnecting authenticated gRPC over a **durable outbox/inbox** with ordered acks + cursors; **FCM is a wake hint only and never represents delivery**; a public-HTTPS device-PoP fetch path exists independent of the tailnet.
- **ADR-007 (REVISED):** Postgres for state; audit is a **per-tenant serialized hash chain with signed checkpoints exported to immutable external storage** (resolves H-20).
- **ADR-008 (retained):** Control-plane agnostic (Tailscale SaaS / headscale); CI tests headscale.
- **ADR-009 (REVISED):** Per-OS enforcement is an explicit, separately specified and bypass-tested architecture (Linux/macOS/Windows), not inferred from Go portability (resolves H-23).
- **ADR-010 (REVISED):** Operational independence from Odyn is proven by dependency-allowlist/SBOM inspection + standalone-deploy test, not a word-ban lint (resolves M-18).
- **ADR-011 (REVISED):** TCP "pause" is an accept-and-hold proxy **with bounded pending-connection/byte budgets and ACL pre-authorization before approval state is created** (resolves H-19); used only inside supported modes.
- **ADR-012 (NEW):** **Multi-tenant by default** (client decision §24). `tenant_id` is pervasive.
- **ADR-013 (NEW):** **Default-deny for protected resources.** Decision lattice `NOT_PROTECTED | ALLOW_WITHOUT_STEP_UP | REQUIRE_STEP_UP | DENY`; unknown identity/destination/protocol/policy/freshness ⇒ DENY (resolves C-12).
- **ADR-014 (REVISED):** **GA includes all required enforcement modes: `HTTP_PROXY`, `OPAQUE_TCP`, `TS_SSH`, and `OPENSSH`.** Generic native applications, databases, raw-TCP APIs, and standard OpenSSH are release-blocking capabilities, not deferred modes.
- **ADR-015 (NEW):** Offline product/tenant root anchors all online signing key-sets; dual authorization required for root/key-set changes (resolves H-08).
- **ADR-016 (NEW):** Production service signing and envelope encryption use **HashiCorp Vault Transit** with separate Ed25519 keys (`request_sig`, `grant_sig`, `policy_sig`, `audit_checkpoint_sig`) and AES-256-GCM keys for envelope encryption. No alternative KMS is part of the required architecture.
- **ADR-017 (NEW):** Android push uses FCM only as a wake hint. Correctness and delivery use the public-HTTPS device-PoP channel; no self-hosted push subsystem is required.
- **ADR-018 (NEW):** Device attestation is mandatory. TEE is the minimum for standard resources; StrongBox is mandatory for high-sensitivity and administrative resources. Software-backed keys are rejected in production.
- **ADR-019 (NEW):** Multi-device routing is sequential, not broadcast: user-selected primary first, then eligible fallbacks after a delivery timeout. This reduces approval fatigue while preserving recovery.
- **ADR-020 (NEW):** Distributed abuse-control counters use an HA **Valkey** cluster with atomic Lua token-bucket operations. Valkey is not a message bus or source of authorization state. If quota state is unavailable, new approval requests fail closed while already authorized live sessions continue subject to revocation freshness.

---

## 6. Repository & artifact layout

Repos: `dnivio/tailscale` (daemon fork), `dnivio/dnivio-approval-service`, `dnivio/dnivio-android`, `dnivio/dnivio-packaging`, `dnivio/dnivio-contracts` (shared protos + OpenAPI + canonicalization vectors), and `dnivio/dnivio-sdk` (Go, Java/Kotlin, JavaScript/TypeScript, Python, and .NET HTTP retry/redemption helpers). Each ships production code, generated bindings, full tests, signed release artifacts where applicable, operator/developer documentation, SBOM, and provenance. `dnivio-contracts` is the sole protocol source; SDKs are generated or conformance-tested against it and do not duplicate authorization logic.

Daemon Dnivio code lives under `dnivio/` plus minimal, interface-narrow hooks in `ipnlocal`, `wgengine/netstack`, `ssh/tailssh`, with documented patch series, CI rebase, and an owner per hook (resolves M-13).

---

## 7. Enforcement architecture & the ingress invariant

### 7.1 The single ingress invariant (DR-ENF-1) — resolves C-02

**DR-ENF-1:** For proxy modes (`HTTP_PROXY`, `OPAQUE_TCP`), no protected socket is reachable by a remote or untrusted local principal except through the Dnivio listener. For SSH modes, the configured SSH listener may accept transport connections, but no account/session authorization can complete without the Dnivio tailssh/PAM/AuthorizedKeysCommand gate. Every alternate listener, authentication method, key source, interface, and backend path is denied. This per-OS, per-resource invariant is continuously verified and tested by §22.2.

### 7.2 Per-OS interception & firewall ownership (DR-ENF-2…5) — resolves C-02, H-23

- **DR-ENF-2 (Linux):** For `HTTP_PROXY` and `OPAQUE_TCP`, Dnivio owns the exposed tailnet address/port; the backend is moved to a Unix socket or private network namespace address. A dedicated nftables table installed atomically drops every direct path to the backend, including IPv4, IPv6, LAN, tailnet, and unauthorized loopback/cgroup access. For SSH modes, nftables restricts ingress to the configured daemon and port while the in-protocol hook is the authorization gate.
- **DR-ENF-3 (Windows):** For `HTTP_PROXY` and `OPAQUE_TCP`, the signed Dnivio service owns the exposed listener and the backend binds loopback under a dedicated service SID. Persistent WFP filters allow backend access only from the Dnivio service SID and deny IPv4/IPv6 direct paths. For Windows OpenSSH, WFP restricts ingress to the configured `sshd` listener and the Dnivio `AuthorizedKeysCommand` is the authorization gate. Filters are installed before listeners start and remain fail closed across service restart.
- **DR-ENF-4 (macOS):** For `HTTP_PROXY` and `OPAQUE_TCP`, Dnivio owns the exposed listener and the backend binds a Unix socket or loopback port accessible only to the dedicated service identity. A signed Network Extension content filter and socket ownership rules deny direct backend paths over IPv4/IPv6. For SSH modes, the filter restricts ingress to the configured listener and PAM/tailssh is the authorization gate. No transparent-proxy entitlement is required.
- **DR-ENF-5 (continuous verification & fail-closed):** The daemon MUST verify required rules/hooks are present on a ≤1s cadence and on any netlink/WFP/NE change event; if a required rule/hook is absent, removed, or the enforcement process is down/starting/upgrading, the resource MUST be unreachable (fail closed), not open.

### 7.3 UDP / QUIC (DR-ENF-6…7) — resolves C-03

- **DR-ENF-6:** UDP to any protected resource is **DENY** by default (IPv4+IPv6). There is no UDP enforcement path in v2.1; a protected resource MUST NOT be reachable over UDP.
- **DR-ENF-7:** For `HTTP_PROXY` resources, QUIC/HTTP-3 (UDP/443) is **blocked** and Alt-Svc is stripped. HTTP-3 is unsupported and is not part of this product specification.

### 7.4 Deployment modes (DR-ENF-8…11) — resolves C-15

Each protected resource is registered with exactly one mode. Policy authors can only select semantics the mode supports (validated at policy publish, resolves H-01/H-06).

| Mode | GA status | Granularity | TLS | SSH account aware |
|---|---|---|---|---|
| `HTTP_PROXY` | **GA (in scope)** | request-aware (REQUEST scope possible) | daemon terminates TLS; backend isolated | n/a |
| `TS_SSH` | **GA (in scope)** | session/connection (account-aware) | n/a | yes (via `tailssh`) |
| `OPAQUE_TCP` | **GA (required)** | connection/session | passthrough | no |
| `OPENSSH` | **GA (required)** | account-aware connection/session | n/a | yes |

- **DR-ENF-8 (`HTTP_PROXY`):** daemon is a TLS-terminating reverse proxy in front of an isolated backend. REQUEST authorizes one normalized logical HTTP request; CONNECTION authorizes requests on one downstream TCP/TLS connection; DURATION uses the capped source-node/resource grant; SESSION uses a random `session_id` carried in a non-persistent, Secure, HttpOnly, SameSite=Strict cookie (or in-memory SDK credential), source-node-bound and recorded in the active-session registry. HTTP/2 streams inherit only the enclosing authorized CONNECTION or SESSION; a REQUEST grant authorizes one stream. WebSocket upgrade consumes a REQUEST/CONNECTION grant and registers the resulting socket as an active session. CONNECT is disabled unless the target is the exact registered resource. Redirect targets are re-evaluated as new resources. HTTP-3 is disabled.
- **DR-ENF-8a (interstitial capabilities — resolves H-02):** the browser interstitial polls status **through the same protected origin**. Two independent ≥256-bit capabilities are issued: (1) a multi-read `poll_cap`, bound to request + tenant + initiating node and usable only on `/.dnivio/status/{request_id}` until request expiry; and (2) a one-time `redeem_cap`, bound to the same request and approved `request_nonce`, used exactly once on reload to redeem the REQUEST grant. Both are stored in `Secure; HttpOnly; SameSite=Strict` cookies with disjoint narrow paths, hashed at rest, rotated on privilege transition, and never sent to the Approval Service by the browser. Responses use `Cache-Control: no-store`, strict CSP, `Referrer-Policy: no-referrer`, no CORS, and constant-shape status bodies. Successful redemption atomically consumes `redeem_cap`, the AGT JTI, and `request_nonce` before forwarding the request.
- **DR-ENF-8b (HTTP request bodies):** GET/HEAD navigations use the interstitial. For non-idempotent or body-bearing HTTP API requests, the proxy does not buffer arbitrary bodies while waiting: it returns a Dnivio authentication challenge before forwarding any bytes, and the client retries after approval using a one-time redemption capability. Official Go, Java/Kotlin, JavaScript/TypeScript, Python, and .NET client helpers are shipped. Configured small idempotent bodies can be encrypted-spooled with hard per-request and per-tenant size limits; spooling is disabled by default.
- **DR-ENF-9 (`TS_SSH`):** enforcement in `tailssh` uses a server-generated SSH connection/session ID and binds the target account. CONNECTION requires approval for each SSH transport connection; SESSION authorizes only the channels belonging to that live SSH connection until its capped expiry. REQUEST is rejected for SSH because arbitrary commands inside an interactive shell cannot be reliably observed as authorization boundaries.
- **DR-ENF-10 (`OPAQUE_TCP`):** the Dnivio daemon owns the exposed protected TCP listener and runs a bounded accept-and-hold proxy. It performs Tailscale ACL pre-authorization and typed-principal resolution before creating approval state, allocates a cryptographically random `connection_id`, waits for approval, then connects to the isolated upstream and splices bytes bidirectionally. TLS remains end-to-end between client and upstream. CONNECTION is the default scope; DURATION is permitted by sensitivity policy; SESSION is bound to the accepted proxy connection. REQUEST is invalid because the protocol is opaque.
- **DR-ENF-10a (`OPENSSH`):** on Linux/macOS, standard OpenSSH uses a Dnivio PAM account module plus a root-owned local Unix-domain control socket to the daemon. `sshd` supplies target account, connection tuple, and PAM transaction ID; the daemon resolves the Tailscale principal independently, verifies socket peer credentials and process identity, creates a random SSH `session_id`, and returns allow/deny only after approval. `UsePAM yes` and the Dnivio account module are continuously verified. On Windows, protected OpenSSH requires `AuthenticationMethods publickey`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `AuthorizedKeysFile none`, no `TrustedUserCAKeys`, and a Dnivio `AuthorizedKeysCommand` helper under a dedicated service account; this disables local/user/admin authorized-key bypasses. The helper performs the daemon exchange and returns the offered authorized key only after approval. Firewall rules prohibit non-tailnet and alternate-port ingress. Configuration drift fails closed. CONNECTION and SESSION scopes are supported; per-command REQUEST is not supported for OpenSSH.
- **DR-ENF-11:** A mode may only offer scopes it can bind (REQUEST requires request awareness; SESSION requires a session id; CONNECTION requires a proxy-owned connection id). Unsupported scope+mode combinations are rejected at policy publish.

### 7.5 Backend isolation (DR-ENF-12…13) — resolves C-02, H-27

- **DR-ENF-12:** An `HTTP_PROXY` or `OPAQUE_TCP` backend MUST bind only to an address unreachable by clients: isolated loopback, Unix socket, dedicated network namespace, or dedicated interface. The proxy reaches it; tailnet/LAN principals cannot. SSH modes instead enforce exclusive listener/configuration ownership under DR-ENF-9/10a.
- **DR-ENF-13 (reachability/configuration probe):** Installation and continuous health checks probe proxy backends from tailnet and LAN vantage points and verify SSH listener/authentication configuration locally and remotely. A directly reachable proxy backend or any SSH bypass path causes registration refusal and fail-closed enforcement.

---

## 8. Cryptography & keys

### 8.1 Algorithms

- Approver device keys: ECDSA P-256 (Android Keystore constraint). Android Keystore controls nonce generation; the application does not require RFC 6979. The app canonicalizes signatures to **low-S** before transmission and the Service rejects malleable/high-S or non-DER/non-canonical signatures.
- Service signers + AGT/request/audit envelopes: Ed25519, wrapped in **COSE_Sign1** with a **single canonical CBOR encoding** (deterministic encoding, sorted keys, definite lengths). Canonicalization vectors live in `dnivio-contracts` and are differential-tested across Go and Kotlin (resolves §22.4 encoding differentials).

### 8.2 Two approver keys (DR-KEY-1…4) — resolves C-07

- **DR-KEY-1 `device_auth`:** hardware-backed, non-exportable, and **not user-authentication-gated**. It can sign background channel handshakes and signed Deny responses while the screen is locked. It cannot approve access; the Service accepts approvals only from `approval_auth`. Compromise of this key permits device impersonation and denial but never grant issuance.
- **DR-KEY-2 `approval_auth`:** hardware-backed, `AUTH_BIOMETRIC_STRONG`, **per-operation** authentication (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`), `setInvalidatedByBiometricEnrollment(true)`. Used **only** to sign Approve responses, so the signature itself proves a fresh strong biometric.
- **DR-KEY-3:** Both keys are independently attested and registered with distinct, asserted key purposes (§14.2). An approval response MUST bind to both the `device_auth`-authenticated channel/device and the `approval_auth` key.
- **DR-KEY-4:** Rotation, invalidation (biometric re-enrollment), loss, re-enrollment, and partial-key-compromise behavior are specified in §15.6.

### 8.3 Attestation verification (DR-KEY-5…6) — resolves H-04, H-05, M-11

- **DR-KEY-5:** Use a maintained attestation verifier that trusts **both** the legacy Google hardware-attestation root **and** the post-2026 RKP root (RKP-only devices since 2026-04-10), via a controlled trust-store process, and checks Google's attestation **certificate revocation list**. Enforce: attestation version, keymaster/security level, key purpose, digest, curve, auth type (`AUTH_BIOMETRIC_STRONG`), origin, rollback resistance where present, **verified-boot state, device-locked state**, OS/vendor/boot **patch-level floors**, and per-tenant device policy. Add Play Integrity / managed-device attestation when app/package/device integrity is required.
- **DR-KEY-6 (StrongBox is not TEE):** every resource has sensitivity `STANDARD | HIGH | ADMIN`. `STANDARD` requires hardware TEE or StrongBox; `HIGH` and `ADMIN` require StrongBox. The attested level is stored in the device record and embedded in every grant. Software-backed keys are rejected in production. Attestation acceptance is validated on a physical-device lab, not an emulator.

### 8.4 Service signing keys & KMS (DR-KEY-7…9) — resolves H-09

- **DR-KEY-7:** Separate keys for `request_sig`, `grant_sig`, `policy_sig`, and `audit_checkpoint_sig`; each versioned by `kid`.
- **DR-KEY-8:** **HashiCorp Vault Transit is the production signing and envelope-encryption provider** (ADR-016). Separate non-exportable Ed25519 Transit keys sign request, grant, policy, and audit-checkpoint payloads; AES-256-GCM Transit keys wrap data-encryption keys. The conformance suite verifies exact prehash/raw-signing behavior, COSE bytes, `kid`↔Vault key-version mapping, latency, quota, HA failover, backup/restore, and outage behavior. Any Vault outage fails closed for issuance. Retries are idempotent by `request_id`/`jti`.
- **DR-KEY-9 (rotation):** new `kid` → distribute pubkey set signed by the offline root (DR-KEY-10) → daemon ack quorum → activate signer → retire old `kid` after max grant TTL. Daemons pin an allowlist of `kid`s with an overlap window.

### 8.5 Offline root & emergency handling (DR-KEY-10…11) — resolves H-08

- **DR-KEY-10:** An **air-gapped product/tenant root** signs the set of online signing public keys. Daemons and apps pin the root, not individual online keys, breaking the circular-trust problem. Root/key-set changes require **dual authorization** (separation of duties). Compromise/revocation/rollback and offline-recovery procedures are documented runbooks (§19) and tested in §22.4.
- **DR-KEY-11 (initial trust):** each deployment has one offline deployment root. Daemons receive its fingerprint in the one-time node bootstrap credential. Android receives it in an administrator-generated enrollment QR/deep-link payload containing service origin, tenant ID, root public key, and expiry. Two root custodians verify the fingerprint against the offline ceremony record over a channel separate from the Approval Service; managed-device configuration can provision the verified fingerprint directly. The Service can never replace the pinned root without the dual-authorized offline-root rotation ceremony.

---

## 9. Signed transaction envelopes & grants

### 9.1 Signed approval **request** envelope (DR-SIG-1…3) — resolves C-08, C-09

The Service signs every approval request as `request_sig` COSE_Sign1:

```
RequestEnvelope (COSE_Sign1, request_sig) {
  protected: { alg: EdDSA, kid, typ: "dnivio-req-v2" }
  payload:   RequestPayload (deterministic CBOR)
}
RequestPayload {
  ver: 2
  request_id, tenant_id, tailnet_id
  issued_at, expires_at                 // request TTL, default 60s
  audience_device_id                    // which approver this is for
  initiating: { src_node_id, src_node_display, src_node_verified: bool,
                requesting_ip, posture_version }
  resource:   ResourceID + { destination_display, destination_verified: bool }
  protocol, ssh_account?                 // account-aware modes
  policy_version, rule_id, scope_requested
  binding:    ScopeBinding (§9.2)        // the concrete flow/session/request binding
  challenge: bytes(32)                    // single-use server nonce
  display_digest: bytes(32)               // hash of the exact fields shown to the user
}
```

- **DR-SIG-1:** The app MUST verify the envelope before rendering: signature against the **pinned `request_sig` trust root** (anchored by the offline root, DR-KEY-10), `alg`/`kid` known, `audience_device_id` == this device, `tenant_id` expected, `challenge` unseen, `issued_at`/`expires_at` valid with skew bound, canonical encoding exact. Unsigned, non-canonical, duplicate, expired, or unknown-key requests are rejected without display (resolves C-08).
- **DR-SIG-2:** Every security-relevant **displayed** field is inside `RequestPayload` and covered by `display_digest`: tenant/tailnet, stable initiating node id + verified display name, `ResourceID` + destination display name + port, protocol, SSH account, policy/rule id, scope, request/expiry times, and `binding` (resolves C-09). Display labels are normalized (Unicode confusables, truncation), and unverified labels are visually distinguished (resolves M-05).
- **DR-SIG-3:** Request-signing key rotation and emergency revocation follow §8.5.

### 9.2 Scope bindings (DR-SIG-4) — resolves C-05, C-06

`ScopeBinding` is mode/scope specific and never a transport 5-tuple:

```
ScopeBinding = oneof {
  HttpRequestBinding {                    // HTTP_PROXY + REQUEST scope
    protected_node_id, src_node_id, method, normalized_authority,
    path_policy_id, http_version, request_nonce   // server-generated; NOT a 5-tuple
  }
  ConnectionBinding  { connection_id }    // proxy-owned immutable id (OPAQUE_TCP/HTTP CONNECTION)
  SessionBinding     { session_id }       // random; TS_SSH SESSION; never persisted (§9.4)
}
```

- **DR-SIG-4:** Browser reload authorization binds to a **server-generated `request_nonce`**, not the abandoned TCP/HTTP-2/HTTP-3 transport (resolves C-05). The daemon publishes grant readiness atomically before the status endpoint may return APPROVED (resolves C-05 race).

### 9.3 Approval **response** & AGT (DR-SIG-5…6, DR-GRANT-1…3) — resolves C-04, C-09, C-10

```
ApprovalResponse (signed) {
  request_id, decision                    // approve | deny
  device_id, key_id                        // approval_auth for approve; device_auth for deny
  signed_at, device_counter                // monotonic anti-clone
  channel_binding, response_nonce
  signature = Sign(key, hash(RequestEnvelope) || decision || device_id || key_id ||
                        signed_at || device_counter || channel_binding || response_nonce)
}
```
- **DR-SIG-5:** The response signs the hash of the full request envelope plus **all** response metadata, including counter and channel binding. `response_nonce` is Service-issued and one-use; `channel_binding` binds the response to the authenticated logical device session but remains valid across transport reconnect through the session cursor. Approve uses `approval_auth`; Deny uses `device_auth`.
- **DR-SIG-6:** `device_counter` is defense in depth, not the sole replay control. It is stored in Android Keystore-backed encrypted storage, increments atomically before signing, and is covered by the signature. The Service updates it with `UPDATE ... WHERE counter < received_counter`; non-increasing values are rejected. Counter loss or rollback forces device re-enrollment. Single-use challenge, response nonce, request state, and inbox deduplication remain authoritative replay defenses.

```
AGT (COSE_Sign1, grant_sig) {
  ver: 2, jti, kid
  tenant_id, tailnet_id
  sub: { oidc_issuer, oidc_subject, user_id }
  src_node_id, src_node_key_epoch          // INITIATING node binding (resolves C-04)
  approver_device_id, approval_key_id, device_security_level   // (resolves H-05)
  nod: protected_node_id, resource: ResourceID, protocol, deployment_mode
  scope, binding: ScopeBinding             // scope-specific (resolves C-05, C-06)
  policy_version, rule_id, authz_epoch     // staleness binding (resolves C-10)
  iat, nbf, exp
}
```

- **DR-GRANT-1 (binding set):** A grant authorizes only the exact `(tenant, sub, src_node, nod, resource, protocol, scope, binding, policy_version, authz_epoch)`. DURATION reuse is keyed by all of these including `src_node` and `policy_version` (resolves C-04, C-10) — another device/node cannot reuse it.
- **DR-GRANT-2 (acceptance checks):** the daemon accepts an AGT only if all hold, else fail closed: signature valid vs pinned `grant_sig`/root for `kid`; `tenant` matches; `nod`==this node; `resource` matches the resolved resource; `protocol`/`deployment_mode` match; `sub` and `src_node` match the live resolved principal with current `src_node_key_epoch` and `node_state==OK`; `device_security_level` ≥ resource policy; `policy_version` ≥ current required and `authz_epoch` current (re-validated against identity/group/tag/posture changes, resolves C-10); `nbf ≤ now ≤ exp`; scope binding matches (HTTP request_nonce / connection_id / session_id); JTI not already consumed for single-use scopes; approver device + keys not revoked.
- **DR-GRANT-3 (TTL and DURATION caps):** REQUEST expires after 30 seconds and is one-use; CONNECTION expires after 120 seconds and is one-use; DURATION is at most 15 minutes for `STANDARD`, at most 5 minutes for `HIGH`, and prohibited for `ADMIN`; SESSION ends with the live session and has an absolute cap of 8 hours for `STANDARD`, 1 hour for `HIGH`, and 30 minutes for `ADMIN`. `HIGH` and `ADMIN` require current online revocation/policy freshness on every use. Policies may shorten but never increase these caps.

### 9.4 SESSION binding & grant cache (DR-GRANT-4…7) — resolves C-06, H-10, H-11

- **DR-GRANT-4:** SESSION grants carry a random `session_id` recorded in request, response, grant, cache key, audit, and an **active-session registry** (§13). They MUST NOT be persisted across process/host restart, MUST terminate when the connection/session closes, and MUST NOT be usable by a parallel connection (resolves C-06).
- **DR-GRANT-5 (cache):** the daemon grant cache is keyed by `(tenant, user, src_node, protected_node, resource, protocol, scope, policy_version, binding-id)`. On-disk persistence (for DURATION/REQUEST consumed-set only — never SESSION) uses OS-protected key storage/TPM, AEAD, versioned records, atomic fsync+rename, anti-rollback metadata, strict file permissions (resolves H-10).
- **DR-GRANT-6 (single-use):** consumption is an **atomic compare-and-swap state machine per JTI**; consumption MUST be persisted **before** traffic is released; in-progress states are recovered on restart; concurrent duplicate use and injected-crash replay are stress-tested (resolves H-11).
- **DR-GRANT-7:** any relevant identity/group/tag/policy/posture/node-ownership change purges matching cached grants (ties to §13).

---

## 10. (reserved — enforcement details folded into §7 and §9)

---

## 11. Approval Service

### 11.1 Surfaces

- gRPC `EnforcementChannel` (daemon↔service, mTLS + live tailnet identity).
- gRPC `ApproverChannel` (app↔service, `device_auth`-signed).
- Public-HTTPS device-PoP fetch/respond fallback (independent of tailnet, resolves H-16).
- REST `/v1` (enrollment, device mgmt, policy authoring, interstitial status, audit export, admin) — full OpenAPI in `dnivio-contracts` (resolves M-03).

**DR-SVC-0 (public device-PoP protocol):** every public-HTTPS fetch/respond call uses WebPKI TLS plus an application signature from `device_auth` over `(method, canonical_path, query_hash, body_hash, tenant_id, device_id, server_nonce, timestamp, request_id)`. Nonces are one-use and expire after 60 seconds; timestamps permit at most 30 seconds of skew; bodies are bounded; replay caches are durable across service instances. Approve responses additionally carry the `approval_auth` signature from DR-SIG-5. TLS alone is never device authentication.

### 11.2 Statefulness (DR-SVC-1) — resolves H-22

- **DR-SVC-1:** the Service is not stateless. The load balancer uses no session affinity. Any instance can accept a reconnect; consumer leases live in `consumer_cursors`, use monotonically increasing fencing tokens, last 15 seconds, and renew every 5 seconds. A new owner can deliver only after atomically incrementing the fence; stale owners' writes and acknowledgements are rejected. Outbox replay starts at `last_acked_seq + 1`. Rolling deploys drain streams for 30 seconds, stop lease renewal, and preserve zero-loss delivery through inbox deduplication. Cross-instance delivery never relies on bare pub/sub.

### 11.3 Approval state machine (DR-SVC-2…3) — resolves H-12, H-13

States: `PENDING → APPROVED → GRANTED`, plus terminal `DENIED | EXPIRED | CANCELLED`.

- **DR-SVC-2:** Legal transitions and transaction boundaries are explicit. The verified approval is persisted first (`APPROVED`); grant minting is **idempotent keyed by `request_id`/`jti`**, so a KMS failure after approval is retried safely and yields **exactly one** grant (`GRANTED`) unless policy explicitly allows replacement (resolves H-12, the v1 "single transition" contradiction).
- **DR-SVC-3 (cancel):** `DaemonToService` includes an authenticated **Cancel** message (resolves H-13). Cancel races approval atomically; a late approval after `CANCELLED` MUST NOT mint a usable grant. All transitions are audited.

### 11.4 Idempotency & contracts (DR-SVC-4) — resolves M-03

- **DR-SVC-4:** all mutating RPC/REST calls take an idempotency key; protobufs specify field numbers/types and a standard error taxonomy; pagination, limits, version negotiation, and backward-compat policy are defined in `dnivio-contracts`. Unknown-field handling and minimum-version negotiation per §21.2.

### 11.5 Durable messaging (DR-SVC-5…6) — resolves H-17, H-22

- **DR-SVC-5:** every grant, denial, cancellation, policy notice, and revocation is written to a **transactional outbox** before dispatch, delivered with **ordered sequence numbers + acknowledgement**, replayed from a per-consumer **cursor** after reconnect, and **deduplicated by stable message id** (inbox). Postgres `LISTEN/NOTIFY` or Redis MAY be used only as a wake-up hint to drain the outbox, never as the delivery guarantee (resolves H-17).
- **DR-SVC-6:** FCM carries only an opaque `request_id` and is a hint; the app fetches the signed envelope over the authenticated channel or public-HTTPS PoP path. Delivery state and timeouts are surfaced to the requesting daemon.

### 11.6 Multi-device approval (DR-SVC-7) — resolves H-14

- **DR-SVC-7:** each user designates one primary approver. The Service sends a device-specific request to the highest-priority eligible device meeting the resource's security level. If the envelope is not fetched within 10 seconds, it sends a distinct child request to the next eligible fallback, continuing sequentially; it never broadcasts simultaneously. The parent request accepts exactly one valid terminal response through atomic CAS, cancels all sibling requests, and audits selection, delivery, timeout, cancellation, and response. A late sibling response is rejected. If no eligible device exists, access is denied.

---

## 12. Policy engine

### 12.1 Protected-resource registry & decision lattice (DR-POL-1…3) — resolves C-12

- **DR-POL-1:** an explicit **protected-resource registry** lists every `ResourceID` and its `deployment_mode`. Enforcement decisions return one of `NOT_PROTECTED | ALLOW_WITHOUT_STEP_UP | REQUIRE_STEP_UP | DENY`.
- **DR-POL-2 (default-deny for protected):** for any registered protected resource, if identity, destination classification, protocol classification, policy evaluation, or policy freshness is unknown/unsupported, the decision is **DENY** (resolves C-12, C-03, DR-RES-3). Bypassing step-up on a protected resource requires an explicit `ALLOW_WITHOUT_STEP_UP` rule.
- **DR-POL-3:** Dnivio never *broadens* Tailscale ACLs; for unprotected resources it returns `NOT_PROTECTED` (no effect). For protected resources it may only restrict.

### 12.2 Formal policy semantics (DR-POL-4…6) — resolves H-06

- **DR-POL-4:** publish a formal JSON schema + normative evaluator. Within a dimension list membership is **OR**; across dimensions is **AND**. Rules have explicit effects `DENY | REQUIRE_STEP_UP | ALLOW_WITHOUT_STEP_UP`. Negative selectors are not supported. Evaluation selects the highest numeric priority; ties at that priority are rejected at publication unless all matching rules have the identical effect and scope. `DENY` cannot be overridden by an equal- or lower-priority rule. Duplicate rule IDs and ambiguous ties are rejected.
- **DR-POL-5:** rules reference **stable resource/identity IDs**, never display names. Evaluation is pure, deterministic, and produces **explainable output** (which rule fired and why).
- **DR-POL-6 (coverage analysis):** before publication, coverage analysis MUST reject uncovered ports, protocols, aliases, and addresses for registered protected resources, and reject scope+mode combinations a mode can't bind (DR-ENF-11).
- **DR-POL-6a (authoritative inventory):** the Service runs explicit Tailscale SaaS and headscale inventory adapters. Each adapter continuously imports stable nodes, users, tags, tag owners, groups, tailnets, node state, and advertised services into versioned tenant snapshots. Policy compilation resolves groups/tags/app groups against one immutable snapshot ID embedded in the bundle. Adapter loss or a snapshot older than 5 minutes prevents policy publication; daemons fail closed when the active bundle's inventory snapshot is stale or unavailable.

### 12.3 Freshness, anti-rollback, distribution (DR-POL-7…9) — resolves H-07

- **DR-POL-7:** a bundle carries `tenant_id`, issuance, not-before, **expiry**, schema version, minimum daemon version, **epoch**, previous-bundle hash, and emergency-revocation metadata; it is signed by `policy_sig` (anchored to the offline root).
- **DR-POL-8:** daemons store **anti-rollback state in protected durable storage**; deleting local state MUST NOT permit an older signed bundle. Monotonic `version`+`epoch` prevents downgrade.
- **DR-POL-9 (max offline age / fail closed):** policy bundles expire 5 minutes after issuance and are refreshed continuously. A daemon with an expired bundle fails closed for **every protected resource**, including rules that previously allowed access without step-up. No operator-configurable fail-open mode exists.

### 12.4 Policy administration tooling (DR-POL-10) — resolves M-08

- **DR-POL-10:** beyond the admin API, ship policy tooling: dry-run/simulation against the resource inventory, affected-resource preview, conflict detection, peer-review/approval workflow with separation of duties + step-up (§14.4), signed publication, rollback-as-new-version, and decision explanation.

---

## 13. Revocation & freshness — resolves C-11, H-17

- **DR-REV-1 (enforceable bound, not "immediate"):** revocation delivery target is ≤2 seconds and the hard freshness bound `R` is **10 seconds**. This bound is not operator-increasable in production.
- **DR-REV-2:** revocations flow over the durable ordered stream (§11.5) with **per-daemon acknowledged sequence numbers**. A daemon whose revocation freshness exceeds `R` **fails closed** for REQUIRE_STEP_UP resources (resolves C-11, H-17, the v1 60s acceptance criterion).
- **DR-REV-3 (active-session termination):** the daemon maintains an **active-session registry** keyed by approver device + grant `jti` + `session_id`/`connection_id`. On a relevant revocation it **terminates live TCP/SSH sessions and HTTP keep-alive**, not only blocks new ones (resolves C-11).
- **DR-REV-4 (scope of revocation):** revocation covers **user, source-node, protected-node, device, key, certificate, and policy** — not only device/grant.
- **DR-REV-5:** DURATION/SESSION grants are re-checked against revocation + identity/posture/policy on **every use**. Tests cover stream loss, out-of-order deltas, daemon restart, DB failover, network partition, and active-session termination (§22.5).

---

## 14. Enrollment, OIDC, node bootstrap, authorization

### 14.1 OIDC (DR-AUTH-1…2) — resolves H-03

- **DR-AUTH-1:** implement OAuth 2.0/OIDC per RFC 9700 BCP: issuer **allowlist**, discovery + JWKS validation, authorization-code + **PKCE**, `state`, `nonce`, **exact** redirect URIs, token audience + lifetime checks, refresh handling, and session revocation. Identity key is **(issuer, subject)**, never subject alone (resolves C-13 collision).
- **DR-AUTH-2:** enrollment tickets are one-time and bound to issuer/subject/device/session/attestation-challenge. Tests cover mix-up, code interception, token replay, issuer confusion, and account reassignment (§22.3).

### 14.2 Device enrollment (DR-AUTH-3) — resolves C-07, H-04

- **DR-AUTH-3:** the app generates **both** `device_auth` and `approval_auth` keys, obtains attestation chains for each (with distinct asserted purposes per DR-KEY-2), and submits them with the enrollment ticket. The Service verifies attestation per DR-KEY-5/6 and records both public keys, attested security level, and purposes. Audit `DEVICE_ENROLL`.

### 14.3 Node bootstrap & mTLS (DR-AUTH-4…6) — resolves C-14

- **DR-AUTH-4:** a protected node bootstraps with a **one-time, audience-bound, tenant-bound** credential issued via an administrator authorization flow. The node's CSR public key is **bound to the authenticated Tailscale stable node id + tenant**.
- **DR-AUTH-5:** certificate profile defines SANs, EKUs, lifetime, rotation, storage (TPM where available), and revocation. The Service verifies **both** mTLS identity **and** live tailnet node identity on **every** stream; mismatches, cloned certs, expired/deleted nodes, and node-key changes without re-authorization are rejected (resolves C-14).
- **DR-AUTH-6:** rogue-registration, cert-cloning, node-id-mismatch, and revoked-cert cases are release gates (§22.3).

### 14.4 RBAC, tenant authz, separation of duties (DR-AUTH-7…9) — resolves C-13

- **DR-AUTH-7:** centralized **deny-by-default** authorization with roles: user, device-admin, policy-author, policy-approver, auditor, security-admin, operator. Every `/devices/{id}`, approval, policy, audit, and push-token operation enforces **object ownership + tenant scope** (resolves IDOR/confused-deputy).
- **DR-AUTH-8:** **separation of duties + step-up** required for policy publication, key/root changes, and audit export (no self-approval).
- **DR-AUTH-9:** cross-tenant and IDOR tests on every endpoint are release gates.

---

## 15. Android approver application

Fork of `tailscale-android`.

### 15.1 Two keys & signing (DR-APP-1) — resolves C-07

- **DR-APP-1:** implement `device_auth` (channel hello + Deny) and `approval_auth` (biometric-gated Approve) per §8.2; the approval UI invokes `BiometricPrompt` only for Approve; Deny signs with `device_auth` and never prompts biometrics.

### 15.2 Request verification & UX (DR-APP-2…3) — resolves C-08, C-09, M-05, M-06

- **DR-APP-2:** verify the signed request envelope (DR-SIG-1) **before rendering**. Render exactly the `display_digest`-covered fields: canonical destination + port, tenant/tailnet, **verified** source device name, target SSH account, requested scope + duration, policy reason, request/expiry countdown, and a risk indicator for unusual context. Normalize Unicode confusables; prevent truncation ambiguity; visually mark unverified labels; require deliberate confirmation.
- **DR-APP-3 (accessibility/localization):** meet WCAG/Android a11y (screen readers, large text, contrast), localize security text, show absolute+relative timestamps with timezone, and provide biometric-unavailable guidance (resolves M-06).

### 15.3 Connectivity (DR-APP-4…5) — resolves H-15, H-16

- **DR-APP-4:** maintain a reconnecting authenticated channel when permitted; **push is only a wake hint**. Provide a durable **public-HTTPS device-PoP fetch/respond path** independent of the tailnet, so a VPN conflict / always-on-VPN / lockdown / disconnected tunnel does not block approvals (resolves H-16). Handle network switching, captive portals, DNS failure, and offline state with clear UX.
- **DR-APP-5:** handle FCM delay/deprioritization, notification-permission denial, and OEM battery restrictions; expose delivery/timeout state to the requester; test on **physical devices and OEM power managers** (resolves H-15).

### 15.4 Device lifecycle & recovery (DR-APP-6) — resolves M-07

- **DR-APP-6:** ship web-based device management (OIDC step-up): enroll, replace, rename, remote-revoke, view status/audit, handle key invalidation, OS reset, stale push token, migration, and decommission. Lost-only-device recovery requires fresh OIDC authentication plus approval by two distinct tenant `device-admin`/`security-admin` principals using phishing-resistant WebAuthn credentials; the requester cannot approve their own recovery. Recovery revokes all old device keys and grants, increments `authz_epoch`, sends security notifications, and writes an externally anchored audit event.

### 15.5 Platform scope

Android is the required approver platform from `design.md`. iOS and desktop approvers are not product requirements and are not represented as deferred deliverables. Protocol contracts remain platform-neutral so additional independently reviewed approvers can be added without changing grant semantics.

### 15.6 Key lifecycle (DR-APP-7)

- **DR-APP-7:** specify rotation, biometric-invalidation re-enroll, loss, re-enroll, and partial-key-compromise (e.g. `device_auth` valid but `approval_auth` invalidated) behavior; a compromised `device_auth` alone MUST NOT authorize approvals.

---

## 16. Audit & observability

### 16.1 Externally anchored audit (DR-AUD-1…4) — resolves H-20, M-16

- **DR-AUD-1:** audit insertion is serialized with a PostgreSQL transaction-scoped advisory lock keyed by `tenant_id`. While holding the lock, the writer allocates the next **tenant-local** sequence from `audit_heads`, reads the prior hash, inserts the event, and advances the head in one transaction. Global `bigserial` is not used as the tenant sequence.
- **DR-AUD-2:** every 60 seconds or 10,000 events, whichever comes first, the Service signs a checkpoint `(tenant_id, first_seq, last_seq, last_hash, created_at)` with `audit_checkpoint_sig` and exports it to S3-compatible object storage with object lock in compliance mode. A checkpoint is not acknowledged complete until the immutable sink confirms retention metadata.
- **DR-AUD-3 (provenance separation):** service-authored event payloads include the originating signed request/response/grant/revocation identifiers and are covered by the hash chain and signed checkpoints. Daemon-reported flow events carry the daemon's mTLS-key signature and producer sequence numbers; missing, duplicate, or out-of-order batches are detected. Per-event Vault signing is not used.
- **DR-AUD-4:** event types cover all `design.md` events plus `GRANT_CONSUMED`, `ENFORCE_DENIED`, `SESSION_TERMINATED`, `BREAKGLASS_*`. Online searchable retention is at least 400 days; immutable checkpointed retention is at least 7 years. Tenants may increase but not reduce these minima. Legal hold overrides deletion. Exports are encrypted to the requesting auditor, require separation-of-duties approval, and are themselves audited. Quarterly restore and full-chain verification are release/operations gates.

### 16.2 Observability (DR-OBS-1) — resolves M-09

- **DR-OBS-1:** OpenTelemetry traces + metrics, structured **redacted** logs, SLO dashboards, and alerts for: bypass attempts, enforcement-integrity loss, revocation lag > R, KMS errors, push failures, outbox backlog, and capacity thresholds. Correlate daemon/service/mobile without leaking secrets.

---

## 17. Data model (Postgres)

Full migrations live in `dnivio-approval-service/migrations`; below is the normative shape (resolves H-21, C-13). All tables carry `tenant_id`; RLS enabled; enums are CHECK-constrained; FKs and unique indexes include `tenant_id`; sensitive columns encrypted (§18).

```sql
CREATE TABLE tenants (id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE users (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
  oidc_issuer text NOT NULL, oidc_subject text NOT NULL,
  email text, created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, oidc_issuer, oidc_subject)
);

CREATE TABLE identity_links (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
  tailnet_id text NOT NULL, tailscale_user_id text NOT NULL,
  user_id uuid NOT NULL,
  inventory_snapshot_id uuid NOT NULL, state text NOT NULL CHECK (state IN ('ACTIVE','REVOKED','CONFLICT')),
  authz_epoch bigint NOT NULL DEFAULT 1,
  UNIQUE (tenant_id, tailnet_id, tailscale_user_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);

CREATE TABLE devices (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
  user_id uuid NOT NULL,
  device_auth_pub bytea NOT NULL, approval_auth_pub bytea NOT NULL,   -- two keys (C-07)
  attestation jsonb NOT NULL, security_level text NOT NULL CHECK (security_level IN ('STRONGBOX','TEE')),
  counter bigint NOT NULL DEFAULT 0,                        -- anti-clone
  push_token text, push_provider text CHECK (push_provider IN ('fcm')),
  state text NOT NULL DEFAULT 'ENROLLED' CHECK (state IN ('ENROLLED','REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, device_auth_pub), UNIQUE (tenant_id, approval_auth_pub),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);

CREATE TABLE nodes (                                        -- protected nodes
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
  ts_stable_node_id text NOT NULL, tailnet_id text NOT NULL,
  cert_serial text NOT NULL, cert_state text NOT NULL CHECK (cert_state IN ('ACTIVE','REVOKED','EXPIRED')),
  node_key_epoch bigint NOT NULL DEFAULT 0, last_seen timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, ts_stable_node_id), UNIQUE (tenant_id, cert_serial)
);

CREATE TABLE resources (                                    -- protected-resource registry (C-12)
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
  protected_node_id uuid NOT NULL,
  service_id text NOT NULL, port int NOT NULL,
  transport text NOT NULL CHECK (transport IN ('TCP')),     -- UDP denied (C-03)
  deployment_mode text NOT NULL CHECK (deployment_mode IN ('HTTP_PROXY','OPAQUE_TCP','TS_SSH','OPENSSH')),
  sensitivity text NOT NULL CHECK (sensitivity IN ('STANDARD','HIGH','ADMIN')),
  required_security_level text NOT NULL CHECK (required_security_level IN ('STRONGBOX','TEE')),
  display_label text,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, protected_node_id, service_id, port),
  FOREIGN KEY (tenant_id, protected_node_id) REFERENCES nodes(tenant_id, id),
  CHECK ((sensitivity = 'STANDARD') OR required_security_level = 'STRONGBOX')
);

CREATE TABLE policies (
  tenant_id uuid NOT NULL REFERENCES tenants(id), version bigint NOT NULL, epoch bigint NOT NULL,
  document jsonb NOT NULL, prev_hash bytea NOT NULL, signature bytea NOT NULL, kid text NOT NULL,
  not_before timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  min_daemon_version text NOT NULL, issued_by uuid REFERENCES users(id),
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE approval_requests (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
  parent_request_id uuid, user_id uuid NOT NULL, device_id uuid, node_id uuid NOT NULL,
  src_node_id text NOT NULL, requesting_ip inet,
  resource_id uuid NOT NULL, protocol text NOT NULL, ssh_account text,
  scope text NOT NULL CHECK (scope IN ('REQUEST','CONNECTION','DURATION','SESSION')),
  binding jsonb NOT NULL, challenge bytea NOT NULL, envelope bytea NOT NULL, envelope_sig bytea NOT NULL,
  policy_version bigint NOT NULL, rule_id text,
  state text NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','APPROVED','GRANTED','DENIED','EXPIRED','CANCELLED')),
  state_version int NOT NULL DEFAULT 0,
  response_decision text, response_sig bytea, response_key_id text, device_counter bigint,
  response_nonce bytea, channel_binding bytea,
  poll_cap_hash bytea, redeem_cap_hash bytea,
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, decided_at timestamptz,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
  FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id),
  FOREIGN KEY (tenant_id, parent_request_id) REFERENCES approval_requests(tenant_id, id)
);

CREATE TABLE grants (
  jti uuid, tenant_id uuid NOT NULL REFERENCES tenants(id),
  request_id uuid NOT NULL,
  user_id uuid NOT NULL, src_node_id text NOT NULL, src_node_key_epoch bigint NOT NULL,
  device_id uuid NOT NULL, node_id uuid NOT NULL, resource_id uuid NOT NULL,
  protocol text NOT NULL, scope text NOT NULL, binding jsonb NOT NULL,
  policy_version bigint NOT NULL, authz_epoch bigint NOT NULL, device_security_level text NOT NULL,
  agt_bytes bytea NOT NULL, kid text NOT NULL,
  iat timestamptz NOT NULL, nbf timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, jti),
  UNIQUE (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES approval_requests(tenant_id, id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
  FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id)
);

CREATE TABLE active_sessions (                              -- for revocation kill (C-11)
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, grant_jti uuid NOT NULL,
  device_id uuid NOT NULL, node_id uuid NOT NULL, session_id text, connection_id text,
  opened_at timestamptz NOT NULL DEFAULT now(), closed_at timestamptz,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, grant_jti) REFERENCES grants(tenant_id, jti),
  FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
  FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id),
  CHECK ((session_id IS NULL) <> (connection_id IS NULL))
);

CREATE TABLE revocations (
  tenant_id uuid NOT NULL, seq bigint NOT NULL,             -- ordered stream (H-17)
  kind text NOT NULL CHECK (kind IN ('user','source_node','protected_node','device','key','cert','grant','policy')),
  target text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, seq)
);

CREATE TABLE outbox (                                       -- durable delivery (H-17/H-22)
  tenant_id uuid NOT NULL, seq bigint NOT NULL, consumer text NOT NULL,
  message_id uuid NOT NULL, payload bytea NOT NULL, acked_at timestamptz,
  PRIMARY KEY (tenant_id, consumer, seq), UNIQUE (tenant_id, message_id)
);

CREATE TABLE inbox (
  tenant_id uuid NOT NULL, consumer text NOT NULL, message_id uuid NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, consumer, message_id)
);

CREATE TABLE consumer_cursors (
  tenant_id uuid NOT NULL, consumer text NOT NULL, last_acked_seq bigint NOT NULL DEFAULT 0,
  lease_owner uuid, lease_fence bigint NOT NULL DEFAULT 0, lease_expires_at timestamptz,
  PRIMARY KEY (tenant_id, consumer)
);

CREATE TABLE audit_heads (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
  last_seq bigint NOT NULL DEFAULT 0, last_hash bytea NOT NULL
);

CREATE TABLE audit_events (
  tenant_id uuid NOT NULL, seq bigint NOT NULL,             -- tenant-local, allocated under advisory lock
  event_type text NOT NULL, producer text NOT NULL CHECK (producer IN ('service','daemon')),
  producer_seq bigint, user_id uuid, device_id uuid, src_node_id text, node_id uuid,
  resource_id uuid, protocol text, result text, request_id uuid, rule_id text, policy_version bigint,
  correlation_id uuid, payload jsonb, occurred_at timestamptz NOT NULL DEFAULT now(),
  prev_hash bytea NOT NULL, row_hash bytea NOT NULL, producer_signature bytea,
  PRIMARY KEY (tenant_id, seq)
);
```

RLS uses separate owner, migrator, service, auditor, and export roles. The application role does not own tables and cannot bypass RLS. Every transaction sets `app.tenant_id` with `SET LOCAL`; pooled connections are reset before reuse. Composite tenant foreign keys are mandatory. State invariants, one grant per approved request, parent/child request winner semantics, terminal-state immutability, tenant-local audit sequence allocation, and capability consumption are enforced by transition functions and constraints with migration, rollback, privilege, and connection-pool leakage tests.

---

## 18. Secrets & sensitive data (DR-SEC-1) — resolves H-28

- **DR-SEC-1:** Vault Transit envelope-encrypts push tokens, OIDC refresh tokens, device metadata, IP addresses, destination labels, and sensitive audit payload fields with tenant-scoped encryption context. Access tokens and enrollment tickets are never persisted plaintext. Backups are encrypted with separate backup keys. Logs and telemetry exclude credentials, signatures, challenges, capabilities, tokens, request bodies, and raw attestation chains. Expired approval request secrets/capability hashes are deleted within 24 hours; push tokens are deleted on revoke plus a 7-day delivery-debug window; operational traces are retained 30 days; audit data follows DR-AUD-4. Every privileged decrypt/export is authorized and audited.

---

## 19. Availability, DR & break-glass

### 19.1 DR (DR-AVL-1) — resolves H-29

- **DR-AVL-1:** the Approval Service SLO is 99.95% monthly availability excluding deliberate fail-closed policy; approval infrastructure is multi-zone; PostgreSQL and Vault use synchronous HA inside the primary region; encrypted backups and WAL/Vault snapshots are copied cross-region. RPO is ≤1 minute and RTO is ≤30 minutes, both proven quarterly by restore drills. Capacity is maintained at 2× measured peak. DB/KMS/DNS/IdP/certificate/service outages fail closed with explicit operator messaging. FCM outage does not block correctness because public HTTPS polling remains available.

### 19.2 Break-glass (DR-BG-1) — resolves H-30

- **DR-BG-1:** emergency access uses a 2-of-3 quorum of named security custodians, each authenticating with a separately stored FIDO2 hardware key. The signed authorization object binds tenant, human user, source node, one protected resource, protocol, reason, incident ID, issue time, and an expiry of at most 15 minutes. It authorizes one CONNECTION or SESSION only, never DURATION, cannot bypass Tailscale ACLs, and is rejected if any field is absent. Issuance and use are written synchronously to the primary audit chain and an independent immutable external sink before access is released; all security administrators are notified. The authorization auto-revokes at expiry and cannot be renewed—another quorum ceremony is required.

---

## 20. Abuse, capacity & resource exhaustion

### 20.1 Rate limiting & quotas (DR-CAP-1) — resolves H-18

- **DR-CAP-1:** Valkey-backed hierarchical token buckets enforce quotas at global, tenant, user, source-node, protected-node, resource, device, and source-IP levels. Baseline hard ceilings are 20 new approvals/minute per user, 60/minute per source node, 300/minute per protected node, 1,000/minute per tenant, and 10,000/minute per deployment; lower tenant/resource limits are configurable, higher limits require an explicit capacity-tested deployment profile. Each user has at most 5 pending approvals and each device receives at most 3 prompts/minute. Weighted fair queuing prevents one tenant from consuming more than 25% of shared pending capacity when others are queued. Valkey unavailability denies new approvals and alerts operators.

### 20.2 Held-connection exhaustion (DR-CAP-2) — resolves H-19

- **DR-CAP-2:** require Tailscale ACL authorization before creating approval state. Default hard bounds are 1 pending connection per `(user, source-node, resource)`; 100 pending connections per resource; 10,000 per protected node; 64 KiB pre-approval buffered bytes per connection; and 256 MiB aggregate pre-approval memory per node. Duplicate attempts with identical full bindings coalesce onto one approval but retain independent connection IDs and never share a single-use grant. Limits are enforced before push, database fan-out, or Vault calls; excess work is deterministically denied and metered.

### 20.3 Performance SLOs (DR-CAP-3) — resolves M-20

- **DR-CAP-3:** the reference deployment supports 10,000 protected nodes, 100,000 enrolled approvers, 1,000 approval requests/second sustained for 15 minutes, 10,000 concurrent pending approvals, and 100,000 live authorized sessions. Excluding human time, p95 request creation-to-mobile-delivery is ≤2 seconds, p95 verified-response-to-flow-release is ≤500 ms, p99 policy evaluation is ≤1 ms, and p99 revocation-to-session-termination is ≤10 seconds. Benchmarks include TLS, COSE, Vault signing, policy evaluation, audit anchoring, and revocation delivery. CPU remains below 70% and memory below 75% at sustained target load; overload sheds new requests without violating revocation or bypass invariants.

---

## 21. Supply chain, config, versioning, errors

### 21.1 Supply chain (DR-SUP-1) — resolves H-24, M-17, M-18

- **DR-SUP-1:** hardened release pipeline: protected branches, two-person review for security-critical code, lockfile/digest-pinned dependencies, SAST/DAST/fuzzing, SBOM + SLSA provenance, reproducible release builds, signed commits/tags/artifacts, TUF update metadata + verification, and a documented upstream-fork intake/merge policy. Odyn independence is proven by SBOM/dependency-allowlist inspection + standalone-deploy test.

### 21.2 Config & versioning (DR-CFG-1, DR-VER-1) — resolves M-14, M-12

- **DR-CFG-1:** versioned typed configuration for daemon/service/mobile; reject unknown/insecure fields; protected file permissions; atomic reload; centrally distributed security config is signed; effective config is safely inspectable.
- **DR-VER-1:** wire contracts use major/minor versions. Components accept the current major and current/previous minor only; a major mismatch fails closed. Unknown protobuf fields are preserved but never interpreted as authorization. Unknown enum values, COSE critical headers, policy fields, or grant claims fail closed. Policy bundles state minimum daemon/mobile versions. Database migrations are expand/contract: old code runs during expansion, all instances upgrade, then contraction occurs in a later signed release. Security-version revocation can immediately raise the minimum accepted version. Rolling upgrade and downgrade rejection are mandatory tests.

### 21.3 Error taxonomy (DR-ERR-1) — resolves M-15

- **DR-ERR-1:** user-safe vs operator-diagnostic error classes with stable codes, localization, retryability. Account-state-leaking reasons ("device revoked", "no approver") are kept in authorized audit/telemetry only; user-facing errors are generic + correlation id.

---

## 22. Mandatory release gates

Release is **prohibited** until all gates pass. These are the acceptance criteria; §23 tasks are not "done" until their gate rows are green. (Adopts `ADVERSARIAL_REVIEW.md` release gates verbatim in intent.)

### 22.1 Functional completeness
`HTTP_PROXY` browser navigation and API, `OPAQUE_TCP` native applications/databases/raw APIs, `TS_SSH`, and `OPENSSH` work per their declared semantics on every supported OS. Every grant scope cannot broaden into another. Enrollment, replacement, revocation, policy administration, audit search/export, and break-glass are complete. Linux/macOS/Windows daemon components and Android app install from signed artifacts and upgrade without bypass windows.

### 22.2 Enforcement bypass matrix (per resource, per OS)
Tailnet DNS + direct IPv4/IPv6; alias/trailing-dot/case variants; direct backend port vs proxy port; TCP/UDP/QUIC/ICMP; tailnet/LAN/localhost/subnet-router/app-connector/alternate-interface; Tailscale Serve / arbitrary local service / Tailscale SSH; firewall disabled / rule deleted / daemon crashed / starting / upgrading / stale config. **Every unmediated path MUST be unreachable.**

### 22.3 AuthN/AuthZ matrix
OIDC mix-up/subject-collision/replay/expired/wrong-audience/missing-PKCE/account-reassignment; cross-tenant + IDOR per object endpoint; role escalation / SoD bypass / policy self-approval; rogue daemon registration / cert cloning / node-id mismatch / revoked cert; tagged/shared/service/subnet/deleted/reassigned nodes.

### 22.4 Cryptographic matrix
Canonical-encoding differentials Go↔Kotlin; unknown alg/key, malformed COSE/CBOR, duplicate keys, non-canonical encodings, invalid curves, **high-S/malleability** policy; request/response/grant replay, cross-tenant/cross-node/cross-protocol replay, binding substitution; key rotation/overlap/emergency-revocation/rollback/offline-root recovery; Android old+new attestation roots, revoked attestation certs, StrongBox/TEE policy, bad boot state, stale patch, biometric-enrollment change, locked/unlocked.

### 22.5 Distributed-systems matrix
Duplicate/delayed/lost/out-of-order messages; DB/KMS/IdP/FCM/DNS/service outage + recovery; instance crash at every transition; partition before/after approval; daemon/mobile reconnect + cursor replay; concurrent approval/deny/cancel/revoke races; active-session revocation + daemon restart.

### 22.6 Abuse & capacity matrix
Approval/held-connection/status-poll/audit-export floods; malformed parser input; push-token churn; tenant fairness + global overload; max pending requests/active sessions; load with audit anchoring + KMS + revocation + policy publish enabled.

### 22.7 Software assurance
Unit/component/integration/physical-device/per-OS-E2E/fuzz/property/load/chaos/penetration tests; SAST + dependency/container/secret scanning; SBOM + provenance + signed artifacts + reproducible-build checks; **independent security review** of crypto, Android key use, OS interception, authorization, tenant isolation, and audit integrity.

Fuzz targets (resolves M-10): CBOR/COSE/protobuf/policy/attestation parsers; property tests for the policy evaluator and the JTI/state machines.

---

## 23. Delivery plan (evidence-based) — resolves C-01, M-01, M-02

C-01 ("no implementation exists") is dispositioned by this plan: every task produces **code + tests + release evidence**, and the traceability CSV (§0) replaces document-only traceability. No task is "done" until its `DR-*` rows have linked code, tests, and the relevant §22 gate is green for its scope. Phases are delivery sequencing only; **no listed capability is optional** (M-01).

**Phase 0 — Foundations & frozen models**
- P0.1 Repos + hardened pipeline (DR-SUP-1): branch protection, signing, SBOM, SAST/secret scan, headscale CI, traceability CSV scaffold. *Gate:* §22.7 pipeline checks green on an empty build.
- P0.2 `dnivio-contracts`: complete protos (field numbers/types, error taxonomy), OpenAPI, COSE/CBOR canonical schemas + **cross-language canonical vectors**. *Gate:* §22.4 encoding-differential test passes Go↔Kotlin.
- P0.3 Crypto core: two-key signing/verify, COSE AGT + request envelope mint/verify, low-S enforcement, KMS adapter + offline-root chain (DR-KEY-7…10). *Gate:* §22.4 crypto subset (replay, malleability, rotation) green.
- P0.4 Data model + RLS migrations (§17) incl. tenant scoping, constraints, transition triggers. *Gate:* migrate up/down + tenant-isolation unit tests green.
- P0.5 Durable outbox/inbox + per-tenant serialized audit + checkpoint export (§11.5, §16). *Gate:* §22.5 messaging subset (dup/out-of-order/replay) green.

**Phase 1 — Identity, enrollment, policy, HTTP_PROXY**
- P1.1 OIDC (RFC 9700) + multi-tenant RBAC + node bootstrap/mTLS (§14). *Gate:* §22.3 fully green.
- P1.2 Two-key enrollment + attestation verifier (both roots + CRL) on a **physical-device lab** (§8.3, §14.2). *Gate:* §22.4 attestation rows green on hardware.
- P1.3 Policy engine: registry, default-deny lattice, formal evaluator, coverage analysis, anti-rollback, freshness (§12). *Gate:* property tests + coverage-rejection tests green.
- P1.4 EnforcementChannel + idempotent state machine + cancel + multi-device (§11). *Gate:* §22.5 approval-race subset green.
- P1.5 OS ingress enforcement for `HTTP_PROXY` on Linux/macOS/Windows + backend-isolation probes (§7). *Gate:* §22.2 bypass matrix green for `HTTP_PROXY` on all three OSes.
- P1.6 `HTTP_PROXY` request-aware enforcement + interstitial (request_nonce binding, atomic readiness), grant cache/persistence/single-use (§7.4, §9). *Gate:* §22.1 browser+API + §22.4 binding-substitution green.
- P1.6a `dnivio-sdk` helpers for Go, Java/Kotlin, JavaScript/TypeScript, Python, and .NET implement challenge polling, one-time redemption, retry safety, timeout/cancellation, and certificate validation. *Gate:* language conformance suite passes against one shared black-box HTTP test server.
- P1.7 Android app: request verification, two-key signing, push-as-hint + public-HTTPS PoP fallback, a11y (§15). *Gate:* §22.6 push/Doze on physical devices green.
- P1.8 Revocation (bounded freshness + active-session kill) + audit anchoring end-to-end (§13, §16). *Gate:* §22.5 revocation/active-session-kill green.

**Phase 2 — OPAQUE_TCP, TS_SSH, OPENSSH, abuse/capacity, DR, break-glass**
- P2.1 `TS_SSH` account-aware enforcement (session-id binding) + ingress invariant + bypass tests. *Gate:* §22.2 + §22.1 SSH green.
- P2.2 `OPAQUE_TCP` accept-and-hold enforcement on Linux/macOS/Windows, including TLS passthrough, database clients, raw APIs, connection/session bindings, and backend isolation. *Gate:* full §22.2 bypass matrix and approve/deny/timeout/revoke matrix green on all OSes.
- P2.3 `OPENSSH` PAM integration, Unix-socket peer authentication, target-account binding, fail-closed configuration monitor, and direct-ingress denial. *Gate:* full SSH bypass and authentication matrix green on Linux and every packaged OpenSSH platform.
- P2.4 Rate limiting/quotas + held-connection bounds + ACL-pre-auth (§20). *Gate:* §22.6 fully green.
- P2.5 DR/SLO/backup/PITR/multi-zone + break-glass (§19). *Gate:* failure drills + break-glass audit/expiry tests green.
- P2.6 Observability (OTel, alerts) + error taxonomy + config safety + version/compat (§16.2, §21). *Gate:* rolling-upgrade-without-bypass test green.

**Phase 3 — Packaging, hardening, independent review, GA**
- P3.1 Signed packaging Linux/macOS/Windows + Android, secure update verification, operator runbooks (install hardening, firewall, isolation, key ceremony, incident response, recovery). *Gate:* §22.1 install/upgrade + runbook exercises green.
- P3.2 Independent security review (§22.7) + penetration test; remediate to zero open Critical/High. *Gate:* external sign-off.
- P3.3 Standalone-deploy + SBOM/dependency-allowlist proof of Odyn independence (ADR-010). *Gate:* §22.7 supply-chain green; quickstart verified.

---

## 24. Final product decisions

- **§24.1 Tenancy:** multi-tenant by default; the same schema and authorization paths serve single-tenant deployments.
- **§24.2 Enforcement modes:** GA requires `HTTP_PROXY`, `OPAQUE_TCP`, `TS_SSH`, and `OPENSSH`. No required `design.md` flow is gated or deferred.
- **§24.3 Push:** FCM is a wake hint only; public HTTPS device-PoP is the correctness path. No self-hosted push service is built.
- **§24.4 Attestation:** attestation is mandatory; TEE is accepted only for `STANDARD`; StrongBox is required for `HIGH` and `ADMIN`.
- **§24.5 Approver platforms:** Android is required. iOS and desktop approvers are not current product requirements.
- **§24.6 Cryptographic service:** HashiCorp Vault Transit is the only production KMS/signing provider.
- **§24.7 Multi-device behavior:** sequential primary/fallback routing; no simultaneous broadcast.

---

## 25. Definition of done (program-level)

1. Every `DR-*` requirement has linked code + tests + operational control + release evidence in the traceability CSV.
2. All §22 gates pass for `HTTP_PROXY`, `OPAQUE_TCP`, `TS_SSH`, and `OPENSSH`.
3. Zero open Critical/High from `ADVERSARIAL_REVIEW.md` (per `REVIEW_RESPONSE.md`) and from the independent review (§22.7, P3.2).
4. Multi-tenant isolation, externally-anchored audit, bounded revocation with active-session kill, and the per-OS ingress invariant are each demonstrated by a passing gate.
5. Signed, provenance-backed artifacts for Linux/macOS/Windows/Android; standalone-deploy proof of Odyn independence.
6. No open product or architecture decision remains in the normative specification.
