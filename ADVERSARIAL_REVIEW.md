# Dnivio Adversarial Design and Engineering Review

**Reviewed:** `design.md`, `ENGINEERING.md`  
**Review date:** 2026-06-19  
**Disposition:** **Not implementation-ready. Do not build or release from the current specification.**

## Executive verdict

The repository contains specifications only. No source code, migrations, tests, deployment manifests, mobile application, packages, or release artifacts exist. None of the documented features is implemented or verifiable.

The engineering specification is materially better than the high-level design, but it overstates completeness and security. Several core flows are internally inconsistent, several claimed controls do not exist in the protocol or data model, and the proposed enforcement hook does not establish a complete destination-side security boundary.

The principal release blockers are:

1. **The enforcement architecture is bypassable.** A `wgengine/netstack` hook and a Tailscale Serve front do not automatically mediate ordinary kernel-path traffic, direct tailnet-IP listeners, UDP/QUIC, local access, LAN access, subnet-routed paths, or arbitrary OpenSSH.
2. **The device-bound requirement is not implemented in the grant.** The AGT has no initiating node/device claim, and reusable grants are cached without the initiating node. Another device owned by the same user can reuse a duration grant.
3. **The browser REQUEST flow cannot satisfy its own connection binding.** Approval is bound to the paused connection, but the interstitial requires a reload that can use a new connection.
4. **One biometric-gated key is assigned incompatible jobs.** It cannot both authenticate background channel startup and require a fresh biometric for each signature. The documented Deny action also cannot sign without invoking biometrics.
5. **Request signing is claimed but not defined.** Important information shown to the user is absent from the signed approval tuple.
6. **“Immediate” revocation is false.** The design allows stale revocation state for at least 60 seconds and does not terminate active sessions.
7. **Authentication, authorization, tenant isolation, and administrative controls are mostly unspecified.**
8. **The audit chain is rewriteable by a database administrator and unsafe under concurrent writers.**
9. **Cross-platform compatibility is asserted from Go portability, not demonstrated by an enforceable per-OS interception design.**
10. **The availability design uses lossy signaling for security-critical delivery and does not define durable recovery.**

The documents must be corrected into one authoritative, internally consistent specification before implementation starts. Every required control below is part of the product, not a deferred enhancement.

## Severity model

| Severity | Meaning |
|---|---|
| Critical | Enables bypass, unauthorized access, approval forgery/confusion, or invalidates a core security claim. |
| High | Creates a likely security failure, operational outage, data exposure, or major rework. |
| Medium | Creates maintainability, usability, verification, or defense-in-depth weakness. |

## Critical findings

### C-01 — No implementation exists

**Evidence:** The workspace contains only `design.md` and `ENGINEERING.md`.

**Impact:** No feature, security control, test, package, or operational procedure is implemented. The status `Implementation-ready (v1.0)` in `ENGINEERING.md:4` is unsupported.

**Required implementation:**

- Build every repository and artifact named by the specification.
- Include production code, migrations, generated protocol bindings, tests, deployment definitions, signed packages, operator documentation, and reproducible releases.
- Replace document-only traceability with requirement-to-code-to-test-to-release evidence.
- Treat the product as incomplete until all supported operating systems and protocols pass adversarial end-to-end tests.

### C-02 — The enforcement point does not mediate all protected traffic

**Evidence:** `ENGINEERING.md:174-176`, `ENGINEERING.md:577-590` place enforcement in Tailscale Serve, `tailssh`, and `wgengine/netstack`.

**Impact:** Tailscale has multiple data paths. A service listening on a tailnet address through the host kernel is not proven to traverse the userspace netstack hook. A user can bypass the Serve front by reaching the backend directly if its listener or firewall permits it. Localhost, LAN, subnet-router, direct host, IPv6, and alternate-interface paths are not covered.

**Required implementation:**

- Define a single, testable ingress invariant: **no protected socket is reachable except through the Dnivio enforcement process**.
- Implement OS-specific interception and firewall ownership:
  - Linux: nftables/eBPF or an equivalently enforceable redirect/drop architecture with atomic rule installation.
  - Windows: Windows Filtering Platform enforcement.
  - macOS: supported Network Extension/content-filter or packet-filter architecture.
- Bind protected upstream services only to an isolated loopback, Unix socket, private namespace, or dedicated interface unreachable by clients.
- Deny direct tailnet-IP, LAN, localhost-from-untrusted-process, subnet-routed, IPv4, IPv6, UDP, and alternate-port bypasses.
- Continuously verify firewall state and fail closed if required hooks or rules are absent.
- Add bypass tests that attempt every alternate ingress path on every supported OS.

### C-03 — UDP and QUIC bypass the TCP-only model

**Evidence:** The policy lists HTTP/HTTPS/TCP/SSH (`ENGINEERING.md:512-516`), while generic enforcement handles inbound TCP (`ENGINEERING.md:585-591`). No UDP policy or deny rule exists.

**Impact:** HTTPS over QUIC uses UDP. Any protected service reachable on UDP, including UDP/443, bypasses a TCP gate. Other UDP services remain entirely outside the model.

**Required implementation:**

- Block UDP to every protected resource unless a separately specified UDP enforcement path authorizes it.
- Explicitly block QUIC/HTTP/3 for protected web services until request-aware QUIC mediation is implemented.
- Add IPv4 and IPv6 UDP bypass tests.
- Make unsupported protocols fail closed rather than fall through to Tailscale ACL allowance.

### C-04 — Grants are not bound to the initiating device

**Evidence:** `design.md` requires binding to the requesting device. AGT claims at `ENGINEERING.md:339-354` contain the protected node (`nod`) and approver device (`dev`) but no initiating node. DURATION reuse is keyed by `(sub,dst,proto)` (`ENGINEERING.md:363`), and the cache key omits source node (`ENGINEERING.md:560`).

**Impact:** A grant approved for Alice on laptop A can authorize Alice from laptop B to the same destination. Shared identities and compromised secondary devices amplify the issue.

**Required implementation:**

- Add immutable initiating principal claims: tailnet ID, stable source node ID, source node key/version, and user ID.
- Bind every grant scope to the initiating node. Bind REQUEST, CONNECTION, and SESSION scopes to a concrete flow/session identifier.
- Key the daemon cache by tenant, user, initiating node, protected node, destination, protocol, scope, policy version, and relevant session/connection identifier.
- Revalidate current source-node ownership and posture on every use.
- Reject tagged/service nodes where no human principal can be established unless an explicit machine-identity policy exists.

### C-05 — Browser REQUEST grants conflict with connection binding

**Evidence:** `conn_binding` identifies the exact paused flow (`ENGINEERING.md:311`, `ENGINEERING.md:333`). Browser approval returns an interstitial and later reloads the URL (`ENGINEERING.md:581`). REQUEST AGTs require `cb` match (`ENGINEERING.md:352`, `ENGINEERING.md:373`).

**Impact:** The reload can use a new TCP connection, source port, HTTP/2 stream, or HTTP/3 connection. Its binding will differ from the paused request, so a correctly enforced grant is rejected. Relaxing the check silently destroys the claimed exact-flow binding.

**Required implementation:**

- Define separate canonical bindings:
  - HTTP request binding: protected node ID, initiating node ID, method, normalized authority, normalized path policy identifier, protocol version, and server-generated request nonce.
  - TCP connection binding: immutable connection ID held by the enforcement proxy.
  - SSH session binding: server-generated SSH session ID plus initiating/protected node identities and target account.
- Do not bind browser reload authorization to an abandoned transport 5-tuple.
- Define HTTP/1.1 keep-alive, HTTP/2 multiplexing, redirects, WebSockets, and retry behavior.
- Atomically publish grant readiness before the status endpoint can return approved.

### C-06 — SESSION scope has no enforceable session binding

**Evidence:** SESSION claims have no session ID or connection binding (`ENGINEERING.md:339-354`), yet are described as tied to a live session (`ENGINEERING.md:364`). The grant cache can persist grants across restart (`ENGINEERING.md:560`).

**Impact:** A SESSION grant can become a broad reusable time-window grant. Persisting it across daemon restart is incompatible with a live-session lifetime.

**Required implementation:**

- Add a cryptographically random session identifier to the request, response, grant, cache key, audit record, and active-session registry.
- Never persist live SESSION grants across process or host restart.
- Terminate the grant when the associated connection/session closes.
- Prevent reuse by parallel connections.
- Test reconnect, process crash, network migration, SSH multiplexing, and concurrent use.

### C-07 — The biometric key design is internally impossible

**Evidence:** The only approver key is configured for per-use strong biometric authentication (`ENGINEERING.md:267`, `ENGINEERING.md:280-285`, `ENGINEERING.md:637-645`). `ApproverHello` must be signed when a background wake opens the channel (`ENGINEERING.md:442`). Deny is also signed, while only Allow invokes `BiometricPrompt` (`ENGINEERING.md:635`).

**Impact:** A background service cannot sign `ApproverHello` with a per-use biometric key before the user interacts. A user cannot send the documented signed denial without biometrics. Implementers will either weaken the key policy or ship flows that fail.

**Required implementation:**

- Use separate keys:
  - `device_auth`: hardware-backed, non-exportable, usable while the device is unlocked or under a tightly scoped authentication policy; used for channel authentication and signed denials.
  - `approval_auth`: hardware-backed, `AUTH_BIOMETRIC_STRONG`, per-operation authentication; used only for approvals.
- Attest and register both keys, with distinct key purposes.
- Bind approval responses to the authenticated channel device and the biometric approval key.
- Specify key rotation, invalidation, loss, re-enrollment, and partial-key compromise behavior.

### C-08 — Approval request signing is claimed but absent

**Evidence:** The glossary and security mapping say requests are signed (`ENGINEERING.md:36`, `ENGINEERING.md:664`). The request schema contains no signature, key ID, or signed envelope (`ENGINEERING.md:300-315`).

**Impact:** The app has no defined way to authenticate a queued request independently of transport, verify request provenance after FCM wake, or detect tampering by an intermediary.

**Required implementation:**

- Define a COSE_Sign1 request envelope with version, algorithm, key ID, tenant, complete canonical payload hash, issuance time, expiry, and audience/device ID.
- Pin a request-signing trust root in the app and define rotation and emergency revocation.
- Verify the signature, audience, tenant, device, nonce, timestamps, and canonical encoding before rendering any request.
- Reject unsigned, ambiguously encoded, duplicate, expired, or unknown-key requests.

### C-09 — Security-relevant display fields are not signed by the approver

**Evidence:** The phone displays requesting device, access type, timestamp, destination, and SSH account (`ENGINEERING.md:633-635`). The signing tuple omits destination label, requesting node, requesting IP, SSH user, expiry, requested scope, and `signed_at` (`ENGINEERING.md:323-331`).

**Impact:** Approval can be presented as one action and recorded or granted as another. This is a transaction-signing failure and enables approval phishing/confusion.

**Required implementation:**

- Sign the hash of the complete canonical request envelope, not a hand-selected tuple.
- Include tenant/tailnet, stable initiating node ID and verified display name, destination stable ID and display name, destination port, protocol, SSH account, policy/rule ID, scope, request/expiry times, and connection/session binding.
- Include decision, device ID, approval key ID, and signed-at value inside the signed response.
- Sanitize and normalize all displayed identifiers; show canonical values rather than attacker-controlled aliases alone.

### C-10 — Reusable grants can authorize the wrong source and stale policy

**Evidence:** DURATION reuse checks only user, destination, and protocol (`ENGINEERING.md:363`). AGTs contain no policy version, rule ID, source node, source posture, or authorization epoch.

**Impact:** A policy tightening, source device compromise, tag change, group removal, or source-node reassignment does not invalidate an existing reusable grant.

**Required implementation:**

- Add tenant, source node, policy version, rule ID, authorization epoch, and source posture/version claims.
- Invalidate cached grants whenever relevant identity, group, tag, policy, posture, or node ownership state changes.
- Cap DURATION scope by resource sensitivity and prohibit it for administrative access unless explicitly authorized by policy.
- Require online freshness for high-risk resources.

### C-11 — Revocation is neither immediate nor complete

**Evidence:** Daemons can poll at intervals up to 60 seconds (`ENGINEERING.md:389-390`). Existing sessions are only rechecked “on reuse”; no active connection termination exists. The acceptance criterion itself allows 60 seconds (`ENGINEERING.md:873-874`).

**Impact:** A stolen device can retain access. Active TCP and SSH sessions survive revocation. A disconnected daemon can continue using stale grants.

**Required implementation:**

- Replace the “immediate” claim with an enforceable bound and then meet it.
- Maintain a durable, ordered revocation stream with per-daemon acknowledged sequence numbers.
- Fail closed when revocation freshness exceeds a small configured bound.
- Track active sessions by approver device and grant JTI and terminate them on revocation.
- Include user, source-node, protected-node, key, certificate, and policy revocation—not only device and grant.
- Test stream loss, out-of-order deltas, daemon restart, database failover, network partition, and active-session termination.

### C-12 — Default allow turns policy omission into access bypass

**Evidence:** No matching rule returns `require:false` (`ENGINEERING.md:526`), and Dnivio never blocks traffic already allowed by Tailscale ACLs (`ENGINEERING.md:533`).

**Impact:** A typo, stale group, unsupported protocol, destination alias, new port, missing policy bundle entry, or resource discovery failure silently removes biometric protection.

**Required implementation:**

- Maintain an explicit protected-resource registry.
- For a protected resource, deny when identity, destination classification, protocol classification, policy evaluation, or policy freshness is unknown.
- Separate `NOT_PROTECTED`, `ALLOW_WITHOUT_STEP_UP`, `REQUIRE_STEP_UP`, and `DENY` decisions.
- Require explicit policy for bypassing step-up on a protected resource.
- Add policy coverage analysis that rejects uncovered ports, protocols, aliases, and addresses before publication.

### C-13 — Administrative authorization and tenant isolation are absent

**Evidence:** REST auth is described only as “user session,” “admin,” “device key,” or daemon mTLS (`ENGINEERING.md:446-457`). The schema has no tenant/tailnet identifier (`ENGINEERING.md:701-800`).

**Impact:** Cross-tenant data access, IDOR, unauthorized device revocation, policy takeover, audit disclosure, and confused-deputy bugs are likely. `oidc_subject` alone can collide across issuers.

**Required implementation:**

- Decide and document single-tenant or multi-tenant operation. For multi-tenant operation, add `tenant_id` to every identity, request, grant, policy, revocation, node, and audit row and every unique/index constraint.
- Store OIDC issuer plus subject as the identity key.
- Implement centralized deny-by-default authorization with roles for user, device administrator, policy author, policy approver, auditor, security administrator, and operator.
- Enforce object ownership on every `/devices/{id}`, approval, policy, audit, and push-token operation.
- Require separation of duties and step-up for policy publication, key changes, and audit export.
- Add cross-tenant and IDOR tests to every API.

### C-14 — Node certificate bootstrap is unspecified

**Evidence:** The service issues an mTLS certificate at daemon registration (`ENGINEERING.md:115`, `ENGINEERING.md:268`), but no registration protocol, authorization method, CSR binding, certificate profile, or renewal/revocation mechanism exists.

**Impact:** An attacker can register a rogue protected node, submit phishing approval requests, consume policy, or receive grants if bootstrap is weak.

**Required implementation:**

- Define one-time, audience-bound, tenant-bound bootstrap credentials and an administrator authorization flow.
- Bind the CSR public key to the authenticated Tailscale stable node ID and tenant.
- Define certificate SANs, EKUs, lifetime, rotation, storage, TPM use, revocation, and compromise response.
- Verify both mTLS identity and live tailnet node identity on every stream.
- Reject certificate/node mismatches, cloned certificates, expired nodes, deleted nodes, and node-key changes without re-authorization.

### C-15 — Generic HTTPS and SSH coverage is overstated

**Evidence:** HTTP enforcement assumes TLS termination through Tailscale Serve (`ENGINEERING.md:579`). SSH-specific enforcement modifies `tailssh` (`ENGINEERING.md:593-600`).

**Impact:** Arbitrary HTTPS services with end-to-end TLS cannot receive an HTTP interstitial without terminating TLS. Standard OpenSSH is not `tailssh`; a generic TCP proxy cannot know the SSH account before protocol authentication. The design claims broader coverage than the architecture supplies.

**Required implementation:**

- Define supported deployment modes exactly:
  - HTTP reverse-proxy mode with TLS termination.
  - Opaque TCP TLS-passthrough mode with connection-level approval only.
  - Tailscale SSH mode with account-aware approval.
  - OpenSSH mode using a PAM/AuthorizedKeysCommand/SSH certificate integration or explicitly connection-only approval.
- Prevent policy authors from selecting request/account semantics unsupported by the deployment mode.
- Prove backend isolation for reverse-proxy deployments.

## High findings

### H-01 — HTTP and TCP enforcement layers can double-prompt or disagree

The TCP layer can approve a connection before the HTTP layer evaluates a request; the HTTP layer can then issue another challenge. Conversely, a duration grant at the TCP layer can suppress intended per-request HTTP approval.

**Required implementation:** Define one authoritative layer per listener, prohibit overlapping enforcement modes, validate configuration, and test HTTP/1.1 keep-alive, HTTP/2 multiplexing, WebSockets, CONNECT, upgrades, and retries.

### H-02 — The interstitial capability-token design is incomplete

`ENGINEERING.md:581` does not define token entropy, issuer, audience, expiry, one-time use, source binding, CSRF protection, SameSite/Secure attributes, referrer policy, CORS, cache control, or whether polling is same-origin. A cookie issued by the protected daemon is not automatically valid at the Approval Service.

**Required implementation:** Proxy status polling through the same protected origin or define a complete cross-origin protocol. Use a short-lived, single-request, sender-bound capability; `Secure`, `HttpOnly`, `SameSite=Strict`, narrow path, no-store responses, strict CSP, no referrer, and constant-shape status output.

### H-03 — OIDC security is not specified

The enrollment flow does not define issuer allowlists, discovery/JWKS validation, authorization code plus PKCE, state, nonce, redirect URI rules, token audience, token lifetime, refresh handling, session revocation, or account linking.

**Required implementation:** Implement OAuth 2.0/OIDC according to current security BCP, use exact redirect URIs and PKCE, bind one-time enrollment tickets to issuer/subject/device/session/challenge, and test mix-up, code interception, token replay, issuer confusion, and account reassignment.

### H-04 — Device attestation verification is incomplete and dated

The specification says “verify to Google Hardware Attestation root” (`ENGINEERING.md:288`) without root rotation, revocation checking, attestation security-level validation details, patch-level policy, verified boot state, device lock state, application integrity, or certificate-chain parser requirements.

As of April 10, 2026, RKP-enabled Android devices exclusively use the new attestation root. Both roots must be handled through a controlled trust-store process. Google also publishes an attestation certificate revocation list.

**Required implementation:** Use a maintained attestation verifier; trust both current roots; fetch and validate revocation status safely; enforce attestation version, keymaster/security level, purpose, digest, curve, auth type, origin, rollback resistance where available, verified boot state, device-locked state, OS/vendor/boot patch floors, and tenant device policy. Add Play Integrity or managed-device attestation if application/package/device integrity is required.

### H-05 — StrongBox fallback weakens an unstated trust level

The product silently falls back from StrongBox to TEE (`ENGINEERING.md:284`, `ENGINEERING.md:626`). This changes resistance to physical and kernel attacks.

**Required implementation:** Make accepted security levels an explicit per-resource policy, display them to administrators, encode the attested level in the device record and grant, and reject devices below policy. Do not call TEE and StrongBox equivalent.

### H-06 — The policy language is ambiguous

The documents do not define whether lists are OR/AND, how multiple subject dimensions combine, canonical host/port formats, IDNA/Unicode, IPv6, DNS changes, service/app group resolution, tag ownership, group snapshots, negative rules, or equal-priority order stability.

**Required implementation:** Publish a formal schema and normative evaluator semantics. Use stable resource IDs rather than display names. Reject duplicate rule IDs and ambiguous ties. Include static linting, conflict detection, coverage analysis, and explainable evaluation output.

### H-07 — Policy freshness and rollback resistance are incomplete

Signed monotonic versions do not define bundle expiry, maximum offline age, epoch reset, disaster recovery, or durable anti-rollback state. Deleting local state can permit an older signed bundle.

**Required implementation:** Add tenant, issuance, not-before, expiry, schema version, minimum daemon version, epoch, previous-bundle hash, and emergency-revocation metadata. Store anti-rollback state in protected durable storage. Fail closed after a defined staleness limit.

### H-08 — Key rotation is circular and lacks emergency handling

The new signer key is distributed through a signed notice/config push (`ENGINEERING.md:805-807`), but policy-key rotation itself requires an already trusted path. No offline root, threshold approval, compromise revocation, or daemon recovery procedure exists.

**Required implementation:** Pin an offline product/tenant root that signs online key sets. Use separate request, grant, policy, and audit signing keys. Define overlap, activation, compromise, revocation, rollback, and offline recovery. Require dual authorization for root/key-set changes.

### H-09 — KMS/HSM support is treated as interchangeable

The spec names GCP KMS, AWS KMS, Vault Transit, and PKCS#11 while requiring Ed25519/COSE behavior. Provider algorithm support, signature encoding, latency, quotas, key versions, and failure behavior differ.

**Required implementation:** Select and fully specify supported providers, conformance tests, deterministic COSE encoding, key-ID mapping, timeout/retry/idempotency rules, and KMS outage behavior.

### H-10 — Grant-cache persistence lacks key management and atomicity

“Encrypted on-disk file” (`ENGINEERING.md:560`) does not define encryption keys, nonce management, integrity, permissions, rollback detection, atomic replacement, crash recovery, or consumed-JTI durability.

**Required implementation:** Use OS-protected key storage/TPM where available, authenticated encryption, versioned records, atomic fsync/rename, anti-rollback metadata, strict permissions, and transactional consume-before-release semantics. Do not persist SESSION grants.

### H-11 — Single-use grants are vulnerable to races and crash windows

A bounded LRU plus persisted set (`ENGINEERING.md:380`) is not a concurrency algorithm. Two goroutines can accept the same JTI, and a crash after release but before persistence can replay it.

**Required implementation:** Use an atomic compare-and-swap state machine per JTI, persist consumption before releasing traffic, define recovery of in-progress states, and stress-test concurrent duplicate use and injected crashes.

### H-12 — The approval state machine contradicts itself

`APPROVED` must transition to `GRANTED`, but `ENGINEERING.md:472` says a request can transition only once and terminal states are immutable. KMS failure after approval is not resolved.

**Required implementation:** Define legal transitions and transaction boundaries precisely. Persist verified approval first, mint idempotently using request ID/JTI, retry safely after KMS failure, and guarantee one grant per approved request unless policy explicitly allows replacement.

### H-13 — Daemon cancellation is missing from the protocol

The state machine includes daemon cancellation (`ENGINEERING.md:469`), but `DaemonToService` has no Cancel message (`ENGINEERING.md:410-417`).

**Required implementation:** Add signed/authenticated cancel, race semantics, acknowledgement, idempotency, and audit handling. Ensure a late approval cannot mint a usable grant after cancellation.

### H-14 — Multi-device approval behavior is undefined

The service “chooses approver device” (`ENGINEERING.md:242`) and the schema stores one device, but selection, fallback, simultaneous delivery, user preference, device trust level, and first-response races are not specified.

**Required implementation:** Define deterministic eligible-device selection or explicit fan-out. If fan-out is supported, bind each device-specific request, accept exactly one terminal response, cancel all others, and audit every delivery and response.

### H-15 — FCM cannot meet the documented reliability guarantee

The app is expected to wake and fetch within three seconds (`ENGINEERING.md:854-855`) and “reliably” prompt under Doze (`ENGINEERING.md:649-650`). FCM high-priority delivery can be delayed or deprioritized, and Android background execution can stop work.

**Required implementation:** Treat push as a hint, not delivery. Maintain a reconnecting authenticated channel when permitted, provide a durable public-HTTPS device-authenticated fetch path, handle notification permission denial and battery restrictions, and expose delivery state/timeouts to the requester. Test real physical devices and OEM power managers.

### H-16 — Requiring the phone to be on the tailnet creates an availability trap

Android supports one active VPN service. The approver can conflict with another VPN, always-on VPN policy, lockdown mode, or a disconnected Tailscale tunnel. FCM wake does not restore guaranteed tailnet reachability.

**Required implementation:** Provide a production public endpoint protected by TLS plus device proof-of-possession, rate limits, and request signatures. Define network switching, captive portal, VPN conflict, DNS failure, and offline behavior. Do not rely solely on tailnet reachability for approval.

### H-17 — Lossy `LISTEN/NOTIFY` is used for security-critical delivery

`ENGINEERING.md:482` uses PostgreSQL `LISTEN/NOTIFY` or Redis pub/sub for cross-instance routing. These are notification mechanisms, not durable work queues, and “or” leaves the architecture undecided.

**Required implementation:** Use a transactional outbox/inbox and durable ordered delivery. Persist every grant, denial, cancellation, policy notice, and revocation before dispatch; acknowledge delivery; replay after reconnect; deduplicate by stable message ID.

### H-18 — Rate limiting and abuse controls appear only in the threat table

`ENGINEERING.md:677` mentions rate limits, debounce, deny-all, and snooze, but no API contract, data model, algorithm, distributed state, acceptance criterion, or overload behavior implements them.

**Required implementation:** Add per-tenant, user, source node, protected node, destination, device, IP, and global quotas; maximum held connections; bounded queues; fair scheduling; backpressure; notification-fatigue controls; and abuse alerts. Fail closed without exhausting the host.

### H-19 — Held TCP connections create a direct resource-exhaustion vector

An attacker can open many protected connections and force sockets, goroutines, memory, FCM requests, database writes, KMS operations, and audit events.

**Required implementation:** Bound pending connections and bytes, require Tailscale ACL authorization before creating approval state, coalesce safely without broadening authorization, rate-limit before push/KMS, and shed load with deterministic denial and metrics.

### H-20 — Audit chaining is not tamper-resistant against the database authority

A database administrator can rewrite rows and recompute the entire chain. Concurrent service instances can race on `prev_hash`. No external checkpoint, signature, WORM storage, or gap detection exists.

**Required implementation:** Serialize per-tenant chain insertion, sign periodic checkpoints with a dedicated audit key, export checkpoints to immutable external storage/SIEM, include event IDs and producer sequence numbers, detect missing/duplicate/out-of-order daemon batches, and verify chains continuously.

### H-21 — The data model omits security-critical state and constraints

Missing or inadequate fields include tenant, OIDC issuer, source node, requesting IP, request envelope/signature, response decision/payload hash/counter/key ID, grant bytes/signature/KID/nbf/connection binding/policy version, node certificate serial/state, revocation sequence, and active sessions. Text enums have no checks; public keys are not unique; state invariants are unenforced.

**Required implementation:** Replace the abbreviated DDL with complete migrations, database constraints, foreign keys, unique indexes, row-level tenant guards where appropriate, encrypted sensitive fields, state-transition enforcement, and migration/rollback tests.

### H-22 — “Stateless service” is inaccurate

Stream ownership, delivery routing, connection presence, and pending response delivery are stateful. PostgreSQL plus KMS alone do not solve stream resumption.

**Required implementation:** Define durable logical sessions, reconnect cursors, lease ownership, fencing tokens, message replay, load-balancer behavior, instance death recovery, and zero-loss rolling deploys.

### H-23 — Cross-platform enforcement is unproven

`ENGINEERING.md:144` infers compatibility from Go and upstream Tailscale support. Interception, firewalling, service management, secure storage, code signing, and update behavior differ materially by OS.

**Required implementation:** Write a per-OS enforcement ADR and threat model. Run full bypass and protocol matrices on Linux, macOS, and Windows, not only compile tests. Do not claim a platform until its destination-side invariant is proven.

### H-24 — Supply-chain and release security are absent

Public forks and signed installers introduce a high-value update channel. The specification omits branch protection, review rules, provenance, dependency pinning, SBOMs, vulnerability scanning, secret scanning, reproducible builds, artifact signing, update verification, and upstream-fork intake.

**Required implementation:** Build a hardened release pipeline with protected branches, two-person review for security code, pinned dependencies, SAST/DAST/fuzzing, SBOM and provenance, reproducible builds where feasible, signed tags/artifacts, secure update metadata, and an upstream merge policy.

### H-25 — Active compromise of the protected node is outside the threat model but unstated

The protected daemon computes bindings, evaluates policy, releases traffic, and reports audit. A compromised protected node can bypass all controls and fabricate flow audit.

**Required implementation:** State this trust assumption explicitly. Harden the node, minimize daemon privileges, isolate signing/identity keys, add measured boot/TPM attestation where required, monitor enforcement integrity, and distinguish service-authored from daemon-reported audit evidence.

### H-26 — Tailscale identity edge cases are not handled

`WhoIs` is treated as always yielding a human user (`ENGINEERING.md:125`, `ENGINEERING.md:556`). Tagged nodes, shared devices, subnet routers, app connectors, node reassignment, expired nodes, and service identities do not fit that assumption.

**Required implementation:** Define identity resolution for each Tailscale principal type. Fail closed when a policy requires a human but no unique current human principal exists. Include stable node identity and tenant in all decisions.

### H-27 — Direct backend and local bypass controls are unspecified

The reverse proxy can be secure only if the upstream cannot be reached directly. No listener, namespace, firewall, Unix-socket, or service-account isolation requirement exists.

**Required implementation:** Make backend isolation part of installation and health checks. Refuse to mark a resource protected if the backend is reachable from a tailnet/LAN address outside the proxy. Include automated reachability probes.

### H-28 — No secrets and sensitive-data handling standard exists

Push tokens, OIDC tokens, device metadata, destination names, IPs, audit payloads, mTLS keys, and local grant caches are sensitive. Encryption, redaction, access, backup, deletion, and retention requirements are missing.

**Required implementation:** Classify data; encrypt sensitive columns and backups; use managed secret storage; redact logs; prohibit secrets in telemetry; rotate credentials; define retention/deletion; and audit privileged reads and exports.

### H-29 — No disaster recovery or availability contract exists

The product is an access gate, so database, KMS, DNS, IdP, FCM, certificate, and service outages directly block access. No RTO/RPO, backup verification, regional failure, restore, or capacity plan exists.

**Required implementation:** Define SLOs, RTO/RPO, tested backups, point-in-time recovery, KMS recovery, multi-zone deployment, capacity limits, failure drills, and explicit fail-closed operator messaging.

### H-30 — No secure break-glass mechanism exists

Fail-closed is correct, but complete loss of the service, phone fleet, KMS, or IdP can lock out all operators. Saying break-glass is out of scope (`ENGINEERING.md:613`) leaves a critical operational safety gap.

**Required implementation:** Build a narrowly scoped, time-limited, quorum-authorized, resource-specific emergency process using separately protected credentials. It must produce immutable external audit, notify security personnel, and automatically expire. It must not be a reusable human bypass token.

## Medium findings

### M-01 — Source-of-truth hierarchy is contradictory

`design.md` is the source of truth, but it contains phased and optional language that conflicts with the demand for a complete system. `ENGINEERING.md` also declares Android-only and multiple unbuilt repositories.

**Required implementation:** Replace both documents with one normative requirements set or a clear hierarchy. Remove “future,” “optional,” “out of scope,” “scaffold,” and phase-exit substitutions for required features.

### M-02 — Requirement traceability is incomplete

The table maps broad objectives to sections, not individual normative requirements, threat controls, code owners, tests, deployment checks, or evidence.

**Required implementation:** Give every requirement a stable ID and map it to design, code, unit/integration/E2E/security tests, operational control, and release evidence.

### M-03 — API specifications are sketches, not contracts

Protobuf definitions omit field numbers/types and error models. OpenAPI does not exist. Pagination, idempotency keys, retry rules, limits, version negotiation, and compatibility are unspecified.

**Required implementation:** Commit complete protobuf/OpenAPI contracts, conformance tests, compatibility policy, generated clients, standard error taxonomy, limits, and idempotency semantics.

### M-04 — Destination canonicalization is unsafe

`destination_id` may be `host:port or service id`. This is ambiguous for aliases, IPv6, DNS rebinding, case, trailing dots, IDNA, port defaults, and renamed hosts.

**Required implementation:** Use typed canonical resource identifiers with tenant, stable protected-node ID, service ID, port, transport, and deployment mode. Keep display labels separate and untrusted.

### M-05 — Approval UX is vulnerable to habituation and confusable labels

The app shows basic labels but no tailnet/tenant, stable device identity, port, scope duration, policy reason, or warning for unusual contexts. Names can be attacker-controlled or Unicode-confusable.

**Required implementation:** Show canonical destination, port, tenant, verified source device, target account, requested duration/scope, and risk context. Normalize Unicode, prevent truncation ambiguity, visually distinguish unverified labels, and require deliberate confirmation.

### M-06 — Accessibility and localization are absent

No requirements cover screen readers, large text, color contrast, localization, right-to-left layout, time-zone display, or biometric-unavailable instructions.

**Required implementation:** Meet WCAG/Android accessibility expectations, localize security text, use absolute and relative timestamps safely, and test accessibility services.

### M-07 — Device lifecycle and recovery UX are incomplete

There is no complete flow for lost-only-device recovery, key invalidation, OS reset, biometric enrollment change, device rename, stale push token, migration, or decommission.

**Required implementation:** Build web-based device management protected by OIDC step-up, recovery verification, clear device status, key replacement, remote revoke, and audit history.

### M-08 — Policy administration UX is missing

An admin API alone is insufficient for safe policy operation. There is no dry run, preview, impact analysis, approval workflow, rollback, diff, or explanation.

**Required implementation:** Build policy validation and administration tooling with simulation against inventory, affected-resource preview, conflict detection, peer review, signed publication, rollback as a new version, and decision explanation.

### M-09 — Observability is not specified

Health endpoints and audit export do not cover metrics, traces, structured logs, alert thresholds, redaction, dashboards, or correlation across daemon/service/mobile.

**Required implementation:** Add OpenTelemetry-compatible traces and metrics, structured redacted logs, SLO dashboards, alerts for bypass/integrity/revocation lag/KMS errors/push failures, and request correlation without leaking secrets.

### M-10 — Test coverage is far too narrow

The 16-case matrix omits success and failure combinations across OS, IP family, HTTP versions, reconnection, concurrency, stale policy, clock rollback, partitions, KMS/DB failure, push delay, multiple devices, and bypass paths.

**Required implementation:** Use the expanded release gates below. Add fuzzing for CBOR/COSE/protobuf/policy/attestation parsers and property tests for policy and state machines.

### M-11 — Emulator attestation acceptance criterion is suspect

`ENGINEERING.md:852-853` expects an emulator with a hardware-attested key to enroll while rejecting software/emulated keys under required attestation. Typical emulator behavior does not prove production hardware-backed attestation.

**Required implementation:** Run attestation acceptance on a physical device lab covering StrongBox, TEE, unsupported StrongBox, biometric changes, locked bootloader, outdated patch, revoked certificate, and both Android attestation roots.

### M-12 — Protocol/version evolution is missing

There is a `ver` claim but no negotiated compatibility, minimum versions, unknown-field behavior, deprecation, rolling upgrade, or downgrade prevention.

**Required implementation:** Define wire, policy, database, mobile, and daemon compatibility matrices; capability negotiation; minimum secure versions; and rolling-upgrade tests.

### M-13 — Fork maintainability is understated

Placing code in a subtree does not isolate hooks in `ipnlocal`, `netstack`, `tailssh`, and command wiring. Those are high-churn and security-sensitive upstream areas.

**Required implementation:** Minimize patches behind narrow upstream-style interfaces, maintain patch-series documentation, continuously rebase in CI, run upstream tests, measure divergence, and assign owners for each hook.

### M-14 — Configuration safety is incomplete

No schema, secure defaults, validation, ownership, reload semantics, or drift detection exists for daemon/service/mobile configuration.

**Required implementation:** Use versioned typed configuration, reject unknown/insecure fields, protect file permissions, support atomic reload, sign centrally distributed security configuration, and expose effective configuration safely.

### M-15 — Error handling leaks or ambiguity are not addressed

Browser, API, TCP, and SSH errors need to balance usability with disclosure. Reasons such as “device revoked” or “user has no approver” can leak account state.

**Required implementation:** Define user-safe and operator-diagnostic error classes, stable codes, localization, retryability, and redaction. Keep detailed reasons in authorized audit/telemetry only.

### M-16 — Audit retention is left configurable without a minimum

A security audit system with no mandatory retention and immutable-export policy can be configured into uselessness.

**Required implementation:** Define minimum online and immutable retention, legal hold, deletion authorization, privacy controls, export encryption, and restore/verification tests.

### M-17 — No secure coding baseline is mandated

The documents do not require ASVS-level API controls, dependency policy, memory/secret handling, static analysis, fuzzing, or security review.

**Required implementation:** Adopt a named secure-development baseline, threat-model review, mandatory code review for security-critical components, parser fuzzing, and pre-release penetration testing.

### M-18 — “No Odyn reference” is a brittle and low-value gate

A string/import lint can false-positive in documentation or miss indirect dependencies. It does not prove operational independence.

**Required implementation:** Enforce dependency allowlists/SBOM inspection and standalone deployment tests. Keep a precise architectural dependency rule rather than a repository-wide word ban.

### M-19 — User and operator documentation is incomplete

The documents do not define installation hardening, firewall requirements, service isolation, certificate recovery, key ceremonies, incident response, or troubleshooting without weakening security.

**Required implementation:** Deliver installation, hardening, operations, recovery, key rotation, incident response, and safe troubleshooting runbooks and validate them through exercises.

### M-20 — Performance targets omit the enforcement bottlenecks

The only target excludes human time and does not cover concurrent holds, KMS signing, database contention from audit chaining, mobile wake latency, proxy throughput, or per-OS packet-path overhead.

**Required implementation:** Define throughput, concurrency, memory, CPU, latency, and overload SLOs for every component and protocol. Benchmark with encryption, audit, policy, and revocation enabled.

## Required architecture corrections

The following architecture is the minimum coherent shape:

1. **Enforcement ownership**
   - Each protected resource has one registered enforcement mode.
   - OS firewall/interception rules force all remote traffic through that mode.
   - Backend reachability checks prove no direct path exists.
   - Unsupported transport or identity states are denied.

2. **Separate device keys**
   - Channel/device authentication key.
   - Per-operation biometric approval key.
   - Both attested, independently rotated, and purpose-restricted.

3. **Signed transaction envelopes**
   - Service signs the complete approval request.
   - Device signs the complete request hash plus decision metadata.
   - Grant reproduces all authorization-relevant identities and bindings.

4. **Typed identities and resources**
   - Tenant/tailnet ID.
   - OIDC issuer and subject.
   - Stable initiating and protected node IDs.
   - Typed destination/service/port/transport/deployment mode.
   - Approver device and key IDs.

5. **Scope-specific grants**
   - REQUEST: logical request nonce, not TCP 5-tuple.
   - CONNECTION: one proxy-owned connection ID.
   - SESSION: one active session ID, never persisted.
   - DURATION: still source-node-, policy-, tenant-, and resource-bound.

6. **Durable messaging**
   - Transactional outbox/inbox.
   - Ordered sequence and acknowledgement for revocations and policies.
   - Reconnect cursors and idempotent replay.
   - Push only wakes; it never represents delivery.

7. **Fail-closed freshness**
   - Maximum policy age.
   - Maximum revocation lag.
   - Explicit behavior for database, KMS, IdP, push, network, and clock failures.
   - Active session termination on relevant revocation.

8. **Externally anchored audit**
   - Per-tenant serialized chain.
   - Signed checkpoints.
   - Immutable external export.
   - Producer sequence/gap detection.

## Required release gates

Release is prohibited until all gates pass.

### Functional completeness

- Browser navigation, HTTP API, opaque TCP, Tailscale SSH, and standard OpenSSH deployment modes work according to their declared semantics.
- Every grant scope is implemented and cannot broaden into another scope.
- Device enrollment, replacement, revocation, policy administration, audit search/export, and emergency access are complete.
- Linux, macOS, Windows, and Android packages are installed from signed release artifacts and upgraded without bypass windows.

### Enforcement bypass matrix

For every protected resource and supported OS, test:

- Tailnet DNS name and direct IPv4/IPv6 address.
- Alternate DNS alias and trailing-dot/case variants.
- Direct backend port and proxy port.
- TCP, UDP, QUIC, ICMP where relevant.
- Tailnet, LAN, localhost, subnet router, app connector, and alternate interface.
- Tailscale Serve, arbitrary local service, Tailscale SSH, and OpenSSH.
- Firewall disabled, rule deleted, daemon crashed, daemon starting, daemon upgrading, and stale configuration.

Every unmediated path must be unreachable.

### Authentication and authorization matrix

- OIDC issuer mix-up, subject collision, replay, expired token, wrong audience, missing PKCE, and account reassignment.
- Cross-tenant access and IDOR for every object endpoint.
- Role escalation, separation-of-duties bypass, and policy self-approval.
- Rogue daemon registration, certificate cloning, node-ID mismatch, and revoked certificate.
- Tagged nodes, shared nodes, service identities, subnet-routed sources, and deleted/reassigned nodes.

### Cryptographic matrix

- Canonical encoding differentials across Go and Kotlin.
- Unknown algorithms/keys, malformed COSE/CBOR, duplicate keys, non-canonical encodings, invalid curves, high-S handling policy, and signature malleability.
- Request/response/grant replay, cross-tenant replay, cross-node replay, cross-protocol replay, and binding substitution.
- Key rotation, overlap, emergency revocation, rollback, and offline-root recovery.
- Android old/new attestation roots, revoked attestation certificates, StrongBox/TEE policy, bad boot state, stale patch, biometric enrollment change, and locked/unlocked state.

### Distributed-systems matrix

- Duplicate, delayed, lost, and out-of-order messages.
- Database/KMS/IdP/FCM/DNS/service outage and recovery.
- Instance crash at every state transition.
- Network partition before and after approval.
- Daemon/mobile reconnect and replay from cursor.
- Concurrent approval/deny/cancel/revoke races.
- Active-session revocation and daemon restart.

### Abuse and capacity matrix

- Approval floods, held-connection floods, status polling floods, audit export abuse, malformed parser input, and push-token churn.
- Tenant fairness and global overload.
- Maximum pending requests and active sessions.
- Load with audit anchoring, KMS signing, revocation delivery, and policy publication enabled.

### Software assurance

- Unit, component, integration, physical-device, per-OS E2E, fuzz, property, load, chaos, and penetration tests.
- SAST, dependency and container scanning, secret scanning, SBOM, provenance, signed artifacts, and reproducible-build checks.
- Independent security review of cryptography, Android key use, OS interception, authorization, tenant isolation, and audit integrity.

## Completeness checklist

| Area | Current state | Required state |
|---|---|---|
| Source implementation | Absent | Complete repositories and release artifacts |
| Universal ingress enforcement | Not established | Proven per OS and bypass-tested |
| HTTP semantics | Internally inconsistent | Request-aware binding and protocol rules |
| TCP enforcement | Concept only | Bounded, isolated, per-OS implementation |
| SSH coverage | Tailscale SSH only | Explicit Tailscale SSH and OpenSSH modes |
| UDP/QUIC | Unaddressed | Denied or fully mediated |
| Device binding | Missing from AGT | Stable source-node claim and validation |
| Biometric key roles | Contradictory | Separate device and approval keys |
| Signed requests | Claimed, undefined | Canonical signed envelope |
| Revocation | Delayed, no session kill | Ordered, freshness-bounded, active termination |
| Policy safety | Default allow | Protected-resource default deny |
| Tenant isolation | Absent | End-to-end tenant scoping and tests |
| Admin authorization | Labels only | Central RBAC and separation of duties |
| OIDC | Sketch | Security-BCP-compliant implementation |
| Node bootstrap | Absent | Authenticated issuance, rotation, revocation |
| Durable delivery | Absent | Outbox/inbox, acknowledgements, replay |
| Audit integrity | Local hash chain | Serialized and externally anchored |
| Data model | Abbreviated/incomplete | Constrained production schema |
| Mobile delivery | Push-dependent | Durable fetch with push as hint |
| Cross-platform proof | Compile/package assertion | Per-OS security and bypass evidence |
| Supply chain | Mostly absent | Hardened, signed, provenance-backed releases |
| Operations/DR | Absent | Tested SLO, backup, recovery, incident procedures |
| Usability/accessibility | Partial | Complete safe workflows and accessibility |

## External references used for this review

- Android Key Attestation, including the 2026 root rotation and revocation guidance: <https://developer.android.com/privacy-and-security/security-key-attestation>
- Android `KeyGenParameterSpec` authentication and biometric invalidation semantics: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder>
- Firebase high-priority message limitations: <https://firebase.google.com/docs/cloud-messaging/android-message-priority>
- Firebase Android background processing constraints: <https://firebase.google.com/docs/cloud-messaging/android/receive-messages>
- OAuth 2.0 Security Best Current Practice, RFC 9700: <https://www.rfc-editor.org/info/rfc9700/>
- OAuth proof-of-possession, RFC 9449: <https://www.rfc-editor.org/info/rfc9449/>
- OWASP Application Security Verification Standard: <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP authorization guidance: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
- OWASP logging guidance: <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>

## Final disposition

The documents do not define a complete, buildable, secure product. The current specification must not be used as implementation authority.

Implementation can start only after:

1. every Critical and High finding has a normative design resolution;
2. one complete enforcement architecture is selected for each supported OS and deployment mode;
3. the protocol, identity, tenant, authorization, persistence, revocation, and audit models are rewritten consistently;
4. all deferred/optional language for required product capabilities is removed; and
5. the release gates above are adopted as mandatory acceptance criteria.
