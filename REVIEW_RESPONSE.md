# Dnivio — Response to Adversarial Review

**Responds to:** [`ADVERSARIAL_REVIEW.md`](./ADVERSARIAL_REVIEW.md)
**Resolved in:** [`ENGINEERING.md`](./ENGINEERING.md) v2.1
**Date:** 2026-06-19

> **v2.1 update:** The v2.0 response left enforcement-mode, KMS, attestation, multi-device, push, and approver-platform choices open. `ADVERSARIAL_REREVIEW.md` identified those gaps. `ENGINEERING.md` v2.1 makes final decisions and supersedes the v2.0 scope notes below wherever they conflict.

## Summary

The review's verdict is **accepted**: v1.0 overstated completeness and security. `ENGINEERING.md` v2.1 incorporates the required architecture corrections, release gates, and completeness checklist. GA now requires `HTTP_PROXY`, `OPAQUE_TCP`, `TS_SSH`, and `OPENSSH`; no required design flow is deferred.

Disposition legend: **Resolved** = a normative requirement now fully addresses it; **Resolved (decision)** = resolved by an explicit recorded product decision; **Accepted/reframed** = the finding is correct and the spec is realigned (notably C-01).

---

## Critical findings

| ID | Finding | Disposition | Resolution location & normative IDs |
|---|---|---|---|
| C-01 | No implementation exists; "v1.0 implementation-ready" unsupported | Accepted/reframed | Header status corrected to "Specification — not code"; §23 delivery plan is evidence-based (code+tests+release evidence per task), §0 traceability CSV replaces document-only traceability. The current correct artifact is the corrected spec; implementation follows §23. |
| C-02 | Enforcement point doesn't mediate all traffic | Resolved | §7.1 **DR-ENF-1** mode-specific invariant; Dnivio owns exposed HTTP/TCP listeners, backends are isolated, and SSH authorization is gated in tailssh/PAM/AuthorizedKeysCommand; §7.2 OS controls + continuous verification; §22.2 bypass matrix. |
| C-03 | UDP/QUIC bypass the TCP-only model | Resolved | §7.3 **DR-ENF-6** (UDP DENY v4+v6), **DR-ENF-7** (QUIC/HTTP-3 blocked, Alt-Svc stripped); **DR-RES-3** unsupported transport ⇒ DENY. |
| C-04 | Grants not bound to initiating device | Resolved | §9.3 AGT carries `src_node_id` + `src_node_key_epoch` + full `sub`; **DR-GRANT-1/2** reuse keyed by initiating node; §3.2 typed principal. |
| C-05 | Browser REQUEST conflicts with connection binding | Resolved | §9.2 `HttpRequestBinding` uses server-generated `request_nonce` (not 5-tuple); **DR-SIG-4** atomic grant-readiness before status=APPROVED; §7.4 DR-ENF-8 defines keep-alive/H2/redirect/WS/retry. |
| C-06 | SESSION scope has no enforceable binding | Resolved | §9.4 **DR-GRANT-4** random `session_id` in request/response/grant/cache/audit/registry; never persisted; terminated on close; no parallel reuse. |
| C-07 | One biometric key given impossible dual roles | Resolved | §8.2 **DR-KEY-1/2** two keys: `device_auth` (channel hello + Deny, no per-use biometric) and `approval_auth` (biometric-gated Approve only); ADR-003. |
| C-08 | Request signing claimed but absent | Resolved | §9.1 **RequestEnvelope** (COSE_Sign1, `request_sig`); **DR-SIG-1** verify-before-render with pinned root, audience, tenant, nonce, canonical encoding. |
| C-09 | Security-relevant display fields not signed | Resolved | §9.1 **DR-SIG-2** all displayed fields inside payload + `display_digest`; **DR-SIG-5** response signs full-envelope hash, not a hand-picked tuple. |
| C-10 | Reusable grants authorize wrong source / stale policy | Resolved | §9.3 AGT adds `policy_version`, `authz_epoch`, `src_node`, `device_security_level`; **DR-GRANT-2** re-validates on every use; **DR-GRANT-3** DURATION caps + admin prohibition + online-freshness; **DR-GRANT-7** purge on change. |
| C-11 | Revocation neither immediate nor complete | Resolved | §13 **DR-REV-1** enforceable freshness bound `R` (replaces "immediate"); **DR-REV-2** ordered acked stream + fail-closed when stale; **DR-REV-3** active-session termination; **DR-REV-4** revokes user/node/device/key/cert/policy. |
| C-12 | Default-allow turns omission into bypass | Resolved | §12.1 **DR-POL-1/2** protected-resource registry + lattice `NOT_PROTECTED/ALLOW_WITHOUT_STEP_UP/REQUIRE_STEP_UP/DENY`; unknown ⇒ DENY; ADR-013. |
| C-13 | AuthZ, tenant isolation, admin controls absent | Resolved (decision) | Multi-tenant (ADR-012); §3.1 **DR-TEN-1…3** tenant_id pervasive + RLS; §14.1 OIDC issuer+subject identity; §14.4 **DR-AUTH-7…9** deny-by-default RBAC + SoD + object ownership; §17 schema. |
| C-14 | Node certificate bootstrap unspecified | Resolved | §14.3 **DR-AUTH-4…6**: one-time tenant/audience-bound bootstrap + admin authz, CSR bound to stable node id, cert profile/rotation/revocation, dual identity check every stream. |
| C-15 | Generic HTTPS/SSH coverage overstated | Resolved (decision) | §7.4 and ADR-014 require all four GA modes: `HTTP_PROXY`, `OPAQUE_TCP`, `TS_SSH`, and `OPENSSH`; Linux/macOS PAM and Windows `AuthorizedKeysCommand` account-aware paths are specified. |

---

## High findings

| ID | Finding | Disposition | Resolution location |
|---|---|---|---|
| H-01 | HTTP/TCP layers double-prompt or disagree | Resolved | §1 one authoritative layer per listener; §7.4 DR-ENF-8 H2/keep-alive/WS/CONNECT/retry rules; DR-ENF-11 mode↔scope validation. |
| H-02 | Interstitial capability-token design incomplete | Resolved | §7.4 **DR-ENF-8a** defines separate ≥256-bit polling and one-time redemption capabilities, same-origin proxying, source/request binding, atomic consume, secure cookies, no-store, CSP, no-referrer, and constant-shape status. |
| H-03 | OIDC security unspecified | Resolved | §14.1 **DR-AUTH-1/2** RFC 9700 BCP: PKCE, exact redirect URIs, state/nonce, issuer allowlist, JWKS, audience/lifetime; tickets bound; mix-up/replay tests. |
| H-04 | Attestation verification incomplete/dated | Resolved | §8.3 **DR-KEY-5** both roots (legacy + post-2026 RKP) + CRL + security-level/patch/verified-boot/lock-state enforcement; physical-device lab. |
| H-05 | StrongBox→TEE fallback weakens unstated level | Resolved | §8.3 **DR-KEY-6** explicit per-resource accepted level, level stored in device record + embedded in grant, reject below policy; StrongBox≠TEE. |
| H-06 | Policy language ambiguous | Resolved | §12.2 **DR-POL-4/5** formal schema + OR-within/AND-across semantics, canonical IDs, dup/tie rejection, explainable eval. |
| H-07 | Policy freshness/rollback incomplete | Resolved | §12.3 **DR-POL-7…9** bundle expiry/epoch/prev-hash/min-version, durable anti-rollback, max-offline-age fail-closed. |
| H-08 | Key rotation circular, no emergency path | Resolved | §8.5 **DR-KEY-10** air-gapped offline root signs online key sets; separate signing keys; dual-auth; compromise/rollback/offline-recovery runbooks. |
| H-09 | KMS/HSM treated as interchangeable | Resolved | §8.4 **DR-KEY-8** selects HashiCorp Vault Transit exclusively and defines COSE conformance, key-version mapping, HA recovery, timeout/retry/idempotency, and fail-closed outage behavior. |
| H-10 | Grant-cache persistence lacks key mgmt/atomicity | Resolved | §9.4 **DR-GRANT-5** OS/TPM key storage, AEAD, versioned, atomic fsync+rename, anti-rollback, strict perms; SESSION never persisted. |
| H-11 | Single-use grants race / crash window | Resolved | §9.4 **DR-GRANT-6** atomic CAS per JTI, persist-consume-before-release, recovery, stress + crash injection. |
| H-12 | State machine contradicts itself | Resolved | §11.3 **DR-SVC-2** explicit transitions incl. APPROVED→GRANTED, idempotent mint keyed by request_id/jti, KMS-failure-safe, exactly-one grant. |
| H-13 | Daemon cancel missing from protocol | Resolved | §11.3 **DR-SVC-3** authenticated Cancel message + race semantics; late approval after CANCELLED cannot mint usable grant. |
| H-14 | Multi-device approval undefined | Resolved | §11.6 **DR-SVC-7** mandates sequential primary/fallback routing, device-specific child requests, atomic first-valid winner, sibling cancellation, and complete audit. |
| H-15 | FCM can't meet reliability guarantee | Resolved | ADR-006 + §15.3 **DR-APP-5** push = hint; reconnecting channel; delivery/timeout surfaced; physical-device/OEM tests. |
| H-16 | Phone-on-tailnet availability trap | Resolved | §15.3 **DR-APP-4** durable public-HTTPS device-PoP fetch/respond path independent of tailnet; VPN-conflict/captive-portal/offline handling. |
| H-17 | Lossy LISTEN/NOTIFY for critical delivery | Resolved | §11.5 **DR-SVC-5** transactional outbox/inbox, ordered seq + ack, reconnect cursors, dedupe; pub/sub only a wake hint. |
| H-18 | Rate limiting only in threat table | Resolved | §20.1 **DR-CAP-1** full quota model (contract+data+algorithm+state+AC), fatigue controls, fail-closed overload. |
| H-19 | Held TCP connections exhaust resources | Resolved | §20.2 **DR-CAP-2** bounded pending conns/bytes, ACL pre-auth before approval state, rate-limit before push/KMS, deterministic shed. |
| H-20 | Audit chain rewriteable by DBA / racey | Resolved | §16.1 **DR-AUD-1…3** per-tenant serialized insert, signed checkpoints to immutable external store, producer seq + gap detection. |
| H-21 | Data model omits security-critical state | Resolved | §17 full DDL: tenant, issuer, src_node, IP, envelope+sig, response fields, grant bytes/sig/kid/nbf/binding, cert serial/state, revocation seq, active_sessions; CHECK enums, FKs, unique indexes, transition triggers. |
| H-22 | "Stateless service" inaccurate | Resolved | §11.2 **DR-SVC-1** durable logical sessions, lease + fencing tokens, reconnect cursors, zero-loss rolling deploy. |
| H-23 | Cross-platform enforcement unproven | Resolved | ADR-009 + §7.2 per-OS ADR/threat model; §22.2 bypass matrix run on Linux/macOS/Windows (not compile tests). |
| H-24 | Supply-chain/release security absent | Resolved | §21.1 **DR-SUP-1** protected branches, 2-person review, pinned deps, SAST/DAST/fuzz, SBOM+provenance, signed/repro artifacts, update verification, upstream-intake policy. |
| H-25 | Protected-node compromise unstated | Resolved | §4.2 **DR-TM-1** explicit trust assumption + hardening; §16 **DR-AUD-3** service-authored vs daemon-reported audit provenance separation. |
| H-26 | Tailscale identity edge cases unhandled | Resolved | §3.2 **DR-ID-1…6** typed principal resolution plus authoritative Tailscale-user-to-OIDC identity links; missing/ambiguous/stale mapping fails closed. |
| H-27 | Direct backend/local bypass unspecified | Resolved | §7.5 **DR-ENF-12/13** backend isolation requirement + reachability probes at install + continuous; refuse "protected" if directly reachable. |
| H-28 | No secrets/sensitive-data standard | Resolved | §18 **DR-SEC-1** data classification, column/backup encryption, managed secrets, log redaction, retention/deletion, privileged-read audit. |
| H-29 | No DR/availability contract | Resolved | §19.1 **DR-AVL-1** SLO/RTO/RPO, tested backups, PITR, KMS recovery, multi-zone, drills, fail-closed operator messaging. |
| H-30 | No secure break-glass | Resolved | §19.2 **DR-BG-1** narrow, time-limited, quorum-authorized, resource-specific, separate creds, immutable external audit, auto-expire, not a reusable token. |

---

## Medium findings

| ID | Disposition | Resolution location |
|---|---|---|
| M-01 source-of-truth hierarchy | Resolved | §0 — ENGINEERING.md is single normative authority; design.md phased/optional language is sequencing-only; no required capability is optional. |
| M-02 traceability incomplete | Resolved | §0 — `DR-*` IDs + traceability CSV (design↔code↔tests↔ops↔release evidence). |
| M-03 API are sketches not contracts | Resolved | §6 `dnivio-contracts` (proto field numbers/types, error taxonomy, OpenAPI, canonical vectors); §11.4 **DR-SVC-4** idempotency/pagination/versioning. |
| M-04 destination canonicalization unsafe | Resolved | §3.3 **DR-RES-1** typed `ResourceID` + normalization; display labels untrusted. |
| M-05 UX habituation/confusable labels | Resolved | §9.1 DR-SIG-2 + §15.2 **DR-APP-2** canonical display, Unicode normalization, unverified-label marking, deliberate confirmation. |
| M-06 accessibility/localization absent | Resolved | §15.2 **DR-APP-3** WCAG/Android a11y, localization, tz-safe timestamps. |
| M-07 device lifecycle/recovery incomplete | Resolved | §15.4 **DR-APP-6** full lifecycle + lost-device recovery via OIDC step-up. |
| M-08 policy admin UX missing | Resolved | §12.4 **DR-POL-10** simulation/preview/conflict-detection/review/rollback/explanation. |
| M-09 observability unspecified | Resolved | §16.2 **DR-OBS-1** OTel traces/metrics, redacted logs, SLO dashboards, bypass/integrity/revocation-lag/KMS/push alerts. |
| M-10 test coverage too narrow | Resolved | §22 expanded gate matrices + fuzz (CBOR/COSE/protobuf/policy/attestation) + property tests. |
| M-11 emulator attestation criterion suspect | Resolved | §8.3 DR-KEY-6 + §23 P1.2 physical-device lab covering StrongBox/TEE/boot/patch/CRL/both roots. |
| M-12 protocol/version evolution missing | Resolved | §21.2 **DR-VER-1** compatibility matrices, capability negotiation, min-secure-version, rolling-upgrade tests. |
| M-13 fork maintainability understated | Resolved | §6 narrow interface hooks, patch-series docs, CI rebase, per-hook owners. |
| M-14 configuration safety incomplete | Resolved | §21.2 **DR-CFG-1** typed versioned config, reject unknown/insecure, atomic reload, signed central security config. |
| M-15 error leak/ambiguity | Resolved | §21.3 **DR-ERR-1** user-safe vs operator-diagnostic classes; account-state reasons kept in audit only. |
| M-16 audit retention no minimum | Resolved | §16.1 **DR-AUD-4** minimum online + immutable retention, legal hold, deletion authz, export encryption, restore tests. |
| M-17 no secure coding baseline | Resolved | §21.1 + §22.7 named baseline (ASVS), mandatory review, fuzzing, pre-release pentest. |
| M-18 no-Odyn gate brittle | Resolved | ADR-010 + §21.1 dependency allowlist/SBOM inspection + standalone-deploy test (replaces word-ban). |
| M-19 operator docs incomplete | Resolved | §23 P3.1 install-hardening/firewall/isolation/key-ceremony/incident-response/recovery runbooks, exercised. |
| M-20 perf targets omit bottlenecks | Resolved | §20.3 **DR-CAP-3** per-component SLOs benchmarked with encryption/audit/KMS/policy/revocation enabled. |

---

## Required architecture corrections (review §"Required architecture corrections")

| Correction | Where adopted |
|---|---|
| 1. Enforcement ownership (one mode/resource, OS firewall, backend probe, deny unsupported) | §7.1–7.5, ADR-013/014 |
| 2. Separate device keys | §8.2 |
| 3. Signed transaction envelopes | §9.1, §9.3 |
| 4. Typed identities and resources | §3.1–3.3 |
| 5. Scope-specific grants | §9.2, §9.4 |
| 6. Durable messaging (outbox/inbox, ordered, cursors, push=hint) | §11.5, ADR-006 |
| 7. Fail-closed freshness (policy/revocation max age, failure behavior, session kill) | §12.3, §13, §19.1 |
| 8. Externally anchored audit | §16.1 |

## Release gates & completeness checklist

All review release-gate matrices are adopted as mandatory acceptance criteria in **§22** (functional, bypass, authn/authz, crypto, distributed-systems, abuse/capacity, software assurance) and wired into the per-task gates in **§23**. The review's completeness checklist rows each map to a `DR-*` requirement and a §22 gate.

---

## Outstanding items

No product or architecture decision remains open. The sole release blocker is implementation and evidence: the repository still contains no code, tests, packages, deployments, or release artifacts.
