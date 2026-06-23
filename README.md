# TSAuth — Biometric Access Verification for Tailscale

**⚠️ Active development. Not yet ready for production use.**

> **⚠️ The full login/authentication and enforcement flow is not yet implemented.**
> OIDC sign-in, device hardware attestation, and the end-to-end approval
> *enforcement* round-trip are still incomplete — the codebase is a
> design-complete skeleton undergoing a security-remediation pass, not a
> functioning access gate. Do not deploy it as a security control. See
> [`TRIAGE.md`](./TRIAGE.md) and [`SECURITY_AUDIT.md`](./SECURITY_AUDIT.md) for
> the finding-by-finding implementation status.

![TSAuth — Biometric Access Verification for Tailscale](./docs/banner.webp)

TSAuth adds biometric step-up verification to [Tailscale](https://tailscale.com/) network access. Before a protected resource can be reached — whether a browser application, native API, database, or SSH server — the user must approve the access attempt using device-native biometrics (fingerprint or facial recognition) on a trusted mobile device.

## How It Works

1. A user or application attempts to reach a protected Tailscale resource.
2. The TSAuth enforcement daemon on the destination node evaluates policy and pauses the connection.
3. An approval request is sent to the user's enrolled Android device.
4. The user verifies their identity with fingerprint or face unlock.
5. Upon approval, a short-lived, cryptographically bound Access Grant Token is issued.
6. The daemon validates the grant and releases the traffic.

The approval device never sees the protected content — only the metadata: destination, requesting device, access type, and timestamp.

## Architecture

| Component | Path | Description |
|---|---|---|
| Contracts & Protocols | `contracts/` | Shared types, COSE/CBOR canonicalization, protobuf, OpenAPI |
| Approval Service | `service/` | Central authorization service in Go |
| Enforcement Daemon | `daemon/` | Per-node enforcement hooks for forked `tailscaled` |
| Android Approver | `android/` | Biometric approval application (Kotlin) |
| Go SDK | `sdk/go/` | HTTP client with automatic challenge/response handling |

## Enforcement Modes

- **HTTP_PROXY** — TLS-terminating reverse proxy with browser interstitial
- **OPAQUE_TCP** — Accept-and-hold proxy for native applications, databases, and raw TCP APIs
- **TS_SSH** — Tailscale SSH session gating with account awareness
- **OPENSSH** — Standard OpenSSH via PAM (Linux/macOS) and AuthorizedKeysCommand (Windows)

## Cryptographic Design

- **COSE_Sign1** with **Ed25519** for all signed envelopes (requests, grants, policies, audit checkpoints)
- **Deterministic CBOR** encoding for cross-language canonicalization
- **Four separate signing keys**: `request_sig`, `grant_sig`, `policy_sig`, `audit_checkpoint_sig`
- **Two Android keys**: `device_auth` (background channel, deny) and `approval_auth` (biometric-gated approve)
- **Air-gapped offline root** signs online key sets
- **HashiCorp Vault Transit** for production signing and envelope encryption
- **Multi-tenant** with Row-Level Security and per-tenant audit chains

## Security Properties

- **Default-deny** for protected resources — unknown identity, protocol, or policy state fails closed
- **Grants bound** to tenant, user, initiating node, destination resource, protocol, scope, and policy version
- **Revocation freshness bound** of 10 seconds with active-session termination
- **Externally anchored audit** — per-tenant serialized hash chain with signed checkpoints to immutable storage
- **Fail-closed** design — policy staleness, revocation lag, KMS outage, or database failure denies access
- **No long-lived bypass tokens** — break-glass requires a 2-of-3 FIDO2 quorum, single session, 15-minute cap

## Quick Start

```bash
# Build all modules
go work sync && make build

# Run tests
make test-unit

# Apply database migrations
DATABASE_URL=postgres://localhost:5432/tsauth make db-migrate

# Start the approval service
cd service && go run ./cmd/approval-service/ -config /etc/tsauth/config.json
```

## Documentation

- [`design.md`](./design.md) — Client requirements
- [`ENGINEERING.md`](./ENGINEERING.md) — Normative build specification (v2.1)
- [`ADVERSARIAL_REVIEW.md`](./ADVERSARIAL_REVIEW.md) — External security review (15 Critical, 30 High findings)
- [`ADVERSARIAL_REREVIEW.md`](./ADVERSARIAL_REREVIEW.md) — Re-review confirming all architecture issues resolved
- [`REVIEW_RESPONSE.md`](./REVIEW_RESPONSE.md) — Finding-by-finding resolution map
- [`SECURITY_AUDIT.md`](./SECURITY_AUDIT.md) — Implementation-status audit of the code vs. the spec (2026-06-19)
- [`TRIAGE.md`](./TRIAGE.md) — Triage of the audit findings to files/fixes, with remediation status
- [`docs/traceability.csv`](./docs/traceability.csv) — Requirement-to-artifact traceability matrix

## Status

This project is in **active development and undergoing a security-remediation pass** against the implementation audit. All 15 Critical and 30 High findings from the adversarial review were resolved **in the specification**, and the Go authorization plane (contracts, service, daemon, SDK) plus the Android approver are **scaffolded** against that spec. A separate code-level audit ([`SECURITY_AUDIT.md`](./SECURITY_AUDIT.md), triaged in [`TRIAGE.md`](./TRIAGE.md)) raised 44 findings; remediation is in progress and tracked by a regression test suite keyed to the finding IDs.

**Addressed so far (each with regression tests):**

- **Fail-closed daemon** — the enforcement daemon builds and now denies by default instead of approving unconditionally (H1, C1)
- **Signature verification** — the service verifies device approval-response signatures before accepting a decision (C3); the daemon verifies Access Grant Token COSE signatures and acceptance checks before caching (C2)
- **Real envelope encryption** — AES-256-GCM replaces the previous repeating-key XOR placeholder (C6)
- **Production crypto gating** — the in-memory signer/encrypter refuse to run outside development mode, and the offline root anchor is loaded from configuration (C5)
- **Tenant isolation hardening** — forced Row-Level Security and a non-owner application role (C9); parameterized `LISTEN/NOTIFY` to close a SQL-injection vector (C10)
- **Grant single-use & anti-replay** — grant consumption plus replay protection that survives daemon restarts (C4, H9)
- **Correctness / concurrency** — thread-safe, tenant-scoped RBAC cache (H4), scoped IDOR ownership check (H5), audit row hashing extended over event detail (H7, partial), and serialized sequence allocation (H8)

**Not yet implemented — the system still does NOT enforce access end-to-end:**

- **Login / OIDC authentication** and ID-token verification — no JWKS / `iss` / `aud` / `nonce` / PKCE validation yet (H11)
- **End-to-end approval round-trip** — the daemon↔service gRPC enforcement channel is not wired, so no live approval actually occurs (the daemon denies everything)
- **Device hardware attestation** verification — still a placeholder (C7)
- **Production KMS** signing and envelope encryption (Vault Transit) — only the dev in-memory path exists (C5)
- **Per-request tenant binding** for RLS, **mTLS/TLS** transport (H10), and **Android Ed25519** verification (H12)

Until these land, the system **does not enforce access** and must not be relied upon as a security control. See [`TRIAGE.md`](./TRIAGE.md) and [`SECURITY_AUDIT.md`](./SECURITY_AUDIT.md) for the full finding-by-finding status. Remaining work also includes the complete test suite, per-OS enforcement bypass proofs, signed packaging, and independent security review.

## License

Licensed under the [BSD 3-Clause License](./LICENSE).

Copyright (c) 2020 Tailscale Inc & contributors. TSAuth retains Tailscale's
copyright and license notice for code derived from the Tailscale project.

---

Built to `ENGINEERING.md` v2.1 by the TSAuth contributors.
