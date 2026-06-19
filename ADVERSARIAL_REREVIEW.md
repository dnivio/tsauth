# Dnivio v2.1 Adversarial Re-review

**Reviewed:** `design.md`, `ENGINEERING.md` v2.0 update, `REVIEW_RESPONSE.md`, prior `ADVERSARIAL_REVIEW.md`  
**Review date:** 2026-06-19  
**Result after corrections:** **Architecture is substantially complete; implementation remains entirely absent and release-blocking.**

## Executive result

The v2.0 update correctly accepted the original audit and repaired most of its core security model: tenant scoping, typed identities/resources, signed request envelopes, source-node-bound grants, two Android keys, bounded revocation, durable messaging, externally anchored audit, default-deny policy, and explicit OS enforcement.

The update was not complete as submitted. It still deferred required native TCP and OpenSSH capabilities, retained unresolved architecture alternatives, omitted the authoritative Tailscale-user-to-OIDC identity link, left browser grant redemption incomplete, failed to sign the device counter, lacked an inventory authority for groups/tags, and declared per-tenant audit sequencing while using a global sequence.

Those defects have been resolved directly in `ENGINEERING.md` v2.1. No client decision remains open.

## Decisions made in v2.1

| Area | Final decision |
|---|---|
| Required modes | GA requires `HTTP_PROXY`, `OPAQUE_TCP`, `TS_SSH`, and `OPENSSH`. |
| Cross-platform ingress | Dnivio owns exposed HTTP/TCP listeners; backends bind isolated addresses. OS controls deny direct backend access. Transparent interception is not the primary architecture. |
| Linux | Atomic nftables policy plus Unix socket/private namespace backend isolation. |
| Windows | Dnivio listener ownership plus WFP service-SID filtering. Windows OpenSSH uses public-key-only `AuthorizedKeysCommand` with all local key-file/CA bypasses disabled. |
| macOS | Dnivio listener ownership plus Unix socket/loopback isolation and Network Extension filtering. No transparent-proxy entitlement is required. |
| Native apps/databases | `OPAQUE_TCP` accept-and-hold proxy with TLS passthrough and connection/session binding. |
| Standard OpenSSH | PAM account gate on Linux/macOS; locked-down `AuthorizedKeysCommand` gate on Windows. |
| Identity | Explicit tenant-scoped link from Tailscale/headscale user ID to OIDC issuer+subject. Ambiguity is deny. |
| Control-plane inventory | Versioned Tailscale/headscale inventory adapters are authoritative for users, groups, tags, nodes, and services. |
| Browser approval | Separate polling and one-time redemption capabilities; redemption atomically consumes capability, nonce, and JTI. |
| HTTP request bodies | No arbitrary pre-approval buffering. Client retries after approval; small idempotent encrypted spooling is bounded and disabled by default. |
| Mobile keys | Background-capable non-auth-gated `device_auth`; per-operation biometric `approval_auth`. |
| Response signature | Covers request hash, decision, key/device IDs, signed time, device counter, logical channel binding, and one-use response nonce. |
| Attestation | Mandatory. TEE for `STANDARD`; StrongBox for `HIGH` and `ADMIN`; software keys denied. |
| KMS | HashiCorp Vault Transit only. Separate Ed25519 signing keys and tenant-context envelope encryption. |
| Push | FCM is a wake hint only. Public HTTPS device proof-of-possession is the correctness path. |
| Multi-device | Sequential primary/fallback routing; no broadcast approval storm. |
| Revocation | Two-second target, ten-second non-configurable hard bound, active-session termination. |
| Policy freshness | Five-minute bundle expiry; stale policy denies every protected resource. |
| Grant lifetimes | Fixed security caps by scope and resource sensitivity. |
| Audit | Tenant-local sequence under PostgreSQL advisory lock; checkpoint every 60 seconds/10,000 events; seven-year immutable retention. |
| Break-glass | 2-of-3 FIDO2 custodian quorum; one resource/session; maximum 15 minutes; external audit before release. |
| Abuse controls | HA Valkey hierarchical token buckets with fixed baseline ceilings and fail-closed loss behavior. |
| Approver platforms | Android is required. iOS/desktop are not disguised as deferred required deliverables. |

## Resolved defects found in the latest update

### R-01 — Required TCP and OpenSSH capabilities were still deferred

v2.0 ADR-014 contradicted `design.md` by shipping only HTTP proxy and Tailscale SSH while denying native application, database, custom TCP, and standard OpenSSH use.

**Resolution:** v2.1 makes all four modes release blocking and adds implementation and release gates for opaque TCP and OpenSSH.

### R-02 — Tailscale identity was not linked to grant OIDC identity

`WhoIs` produces a Tailscale/control-plane identity; enrollment produces an OIDC issuer/subject. Treating them as identical would allow mismapping or make grant validation impossible.

**Resolution:** `DR-ID-6` adds an authoritative, versioned identity link. Missing, conflicting, or stale links deny and invalidate grants.

### R-03 — Browser request nonce had no redemption mechanism

v2.0 bound the grant to a request nonce but did not specify how a reloaded browser request proved possession of that nonce.

**Resolution:** `DR-ENF-8a` defines separate polling and one-time redemption capabilities and an atomic consume-before-forward transaction.

### R-04 — Approval signature omitted the anti-replay counter

The response structure contained `device_counter`, but the signature formula omitted it.

**Resolution:** `DR-SIG-5/6` signs the counter, logical channel binding, and response nonce, and defines atomic server-side counter advancement.

### R-05 — Policy groups/tags had no authoritative data source

The evaluator referred to group/tag snapshots without defining how Tailscale SaaS and headscale state entered or invalidated policy.

**Resolution:** `DR-POL-6a` adds versioned inventory adapters and a five-minute hard freshness rule.

### R-06 — Per-tenant audit used a global sequence

The DDL used `bigserial` despite claiming per-tenant serialized chains.

**Resolution:** `audit_heads` and transaction-scoped advisory locking allocate tenant-local sequences atomically.

### R-07 — Outbox design omitted inbox and cursor tables

The text required deduplication, replay cursors, leases, and fencing, but the schema only included outbox rows.

**Resolution:** v2.1 adds inbox, cursor/lease/fence state, fixed lease timing, reconnect behavior, and no-affinity rolling deployment.

### R-08 — KMS provider remained an implementation choice

“Supported providers are selected later” is not an architecture.

**Resolution:** Vault Transit is the only production cryptographic service. Outage, HA, rotation, key mapping, and conformance behavior are normative.

### R-09 — StrongBox policy remained configurable without a decision

**Resolution:** TEE is accepted for `STANDARD`; StrongBox is mandatory for `HIGH` and `ADMIN`.

### R-10 — Multi-device routing still offered two incompatible models

**Resolution:** primary-first sequential fallback is mandatory; sibling requests share a parent transaction and first valid terminal response wins.

### R-11 — Break-glass was a principle, not a protocol

**Resolution:** 2-of-3 FIDO2 quorum, explicit signed claims, single session/connection, 15-minute cap, no renewal, and immutable audit-before-release.

### R-12 — OS interception choices were alternatives rather than decisions

The updated review initially considered nftables/eBPF, WFP redirection, and macOS transparent proxying. That would create three complex packet-redirection products and substantial bypass risk.

**Resolution:** explicit listener ownership and backend isolation are the common architecture. OS facilities enforce isolation rather than carrying authorization semantics.

### R-13 — Windows OpenSSH could bypass `AuthorizedKeysCommand`

OpenSSH checks configured authorized-key files before `AuthorizedKeysCommand`.

**Resolution:** protected Windows OpenSSH disables `AuthorizedKeysFile` and trusted CAs, requires public-key authentication, and accepts keys only through the Dnivio command.

### R-14 — “Define later” remained in availability, capacity, retention, and compatibility

**Resolution:** v2.1 sets concrete revocation, policy, grant, audit, availability, recovery, capacity, rate-limit, retention, and compatibility values.

## Remaining release blocker

### C-R1 — There is still no implementation

The workspace still contains only Markdown specifications. There is no:

- daemon fork or OS enforcement component;
- Approval Service;
- Android app;
- OpenSSH PAM/Windows helper;
- protobuf/OpenAPI/COSE contract repository;
- database migration;
- Vault/Valkey/PostgreSQL deployment;
- package, installer, update metadata, SBOM, or provenance;
- unit, integration, physical-device, OS bypass, fuzz, load, chaos, or penetration test.

No security claim is currently demonstrated. `ENGINEERING.md` is a build authority, not evidence that the product exists.

## Mandatory implementation verification

The following proofs are required before any release designation:

1. **Listener ownership proof:** port scans and local-process tests show that only Dnivio or the approved SSH daemon can accept protected ingress.
2. **Backend isolation proof:** direct IPv4/IPv6, tailnet, LAN, loopback, alternate-interface, namespace, and service-account access fails.
3. **OS failure proof:** daemon crash, service restart, firewall/filter deletion, package upgrade, and boot sequencing remain closed.
4. **Identity proof:** Tailscale SaaS and headscale adapters correctly link stable node/user identity to OIDC and invalidate drift.
5. **Protocol proof:** browser, API retry, HTTP/2, WebSocket, native TCP/database, Tailscale SSH, Linux/macOS OpenSSH PAM, and Windows OpenSSH command paths pass approve/deny/timeout/revoke tests.
6. **Crypto proof:** cross-language canonical vectors, malformed COSE/CBOR, high-S ECDSA, response-counter tampering, nonce replay, key rotation, root recovery, and Vault failover pass.
7. **Android proof:** physical TEE/StrongBox devices, both attestation roots, certificate revocation, locked-screen channel behavior, biometric invalidation, and OEM background restrictions pass.
8. **Distributed proof:** every state transition survives duplication, crash, partition, delayed response, stale lease, and replay.
9. **Tenant proof:** RLS owner bypass, pooled-connection tenant leakage, IDOR, export authorization, and cross-tenant message/audit delivery fail securely.
10. **Independent proof:** external penetration testing and architecture review close every Critical and High finding.

## Final disposition

`ENGINEERING.md` v2.1 now makes the previously open architecture decisions and is materially suitable as a normative implementation specification.

The product itself remains **not implemented and not releasable**. Completion means passing the evidence gates with built artifacts; it does not mean producing more design text.

## Primary references checked

- Android key attestation and certificate-root/revocation handling: <https://developer.android.com/privacy-and-security/security-key-attestation>
- Android Keystore authentication controls: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder>
- HashiCorp Vault Transit Ed25519 support: <https://developer.hashicorp.com/vault/docs/secrets/transit>
- Microsoft WFP connection/bind redirection and tracking: <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection>
- Apple Network Extension transparent proxy API: <https://developer.apple.com/documentation/NetworkExtension/NETransparentProxyProvider>
- OpenSSH `AuthorizedKeysCommand` precedence and ownership requirements: <https://man.openbsd.org/sshd_config>
