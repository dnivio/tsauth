-- Dnivio Approval Service — Database Schema
-- Per ENGINEERING.md v2.1 §17 (Data model)
-- Migration: 001_initial_schema
--
-- All tables carry tenant_id. RLS is enabled. Enums are CHECK-constrained.
-- FKs and unique indexes include tenant_id. Sensitive columns are noted for encryption (§18).

BEGIN;

-- ─── Extensions ────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "pgcrypto";       -- for gen_random_bytes()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";       -- for UUID generation

-- ─── Tenants (§3.1, DR-TEN-1) ─────────────────────────────────────────────

CREATE TABLE tenants (
    id          uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- ─── Users (§14.1, DR-AUTH-1) ─────────────────────────────────────────────

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    oidc_issuer     text NOT NULL,
    oidc_subject    text NOT NULL,
    email           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, oidc_issuer, oidc_subject)
);

-- ─── Identity Links (§3.2, DR-ID-6) ────────────────────────────────────────

CREATE TABLE identity_links (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    tailnet_id          text NOT NULL,
    tailscale_user_id   text NOT NULL,
    user_id             uuid NOT NULL,
    inventory_snapshot_id uuid NOT NULL,
    state               text NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED', 'CONFLICT')),
    authz_epoch         bigint NOT NULL DEFAULT 1,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, tailnet_id, tailscale_user_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);

-- ─── Devices (§8.2, §15, DR-KEY-1…6) ──────────────────────────────────────

CREATE TABLE devices (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    user_id             uuid NOT NULL,
    device_auth_pub     bytea NOT NULL,          -- hardware-backed, non-exportable
    approval_auth_pub   bytea NOT NULL,          -- hardware-backed, AUTH_BIOMETRIC_STRONG
    attestation         jsonb NOT NULL,          -- verified attestation chains
    security_level      text NOT NULL CHECK (security_level IN ('STRONGBOX', 'TEE')),
    counter             bigint NOT NULL DEFAULT 0, -- monotonic anti-clone counter
    push_token          text,                    -- encrypted at rest (§18)
    push_provider       text CHECK (push_provider IN ('fcm')),
    state               text NOT NULL DEFAULT 'ENROLLED' CHECK (state IN ('ENROLLED', 'REVOKED')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, device_auth_pub),
    UNIQUE (tenant_id, approval_auth_pub),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
);

-- ─── Protected Nodes (§14.3, DR-AUTH-4…6) ─────────────────────────────────

CREATE TABLE nodes (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    ts_stable_node_id   text NOT NULL,           -- Tailscale STABLE node id
    tailnet_id          text NOT NULL,
    cert_serial         text NOT NULL,           -- mTLS certificate serial
    cert_state          text NOT NULL CHECK (cert_state IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    node_key_epoch      bigint NOT NULL DEFAULT 0,
    last_seen           timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, ts_stable_node_id),
    UNIQUE (tenant_id, cert_serial)
);

-- ─── Protected Resources (§12.1, DR-POL-1, DR-RES-1…3) ────────────────────

CREATE TABLE resources (
    id                      uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id               uuid NOT NULL REFERENCES tenants(id),
    protected_node_id       uuid NOT NULL,
    service_id              text NOT NULL,
    port                    int NOT NULL,
    transport               text NOT NULL CHECK (transport IN ('TCP')),
    deployment_mode         text NOT NULL CHECK (deployment_mode IN ('HTTP_PROXY', 'OPAQUE_TCP', 'TS_SSH', 'OPENSSH')),
    sensitivity             text NOT NULL CHECK (sensitivity IN ('STANDARD', 'HIGH', 'ADMIN')),
    required_security_level text NOT NULL CHECK (required_security_level IN ('STRONGBOX', 'TEE')),
    display_label           text,                -- encrypted at rest (§18)
    created_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, protected_node_id, service_id, port),
    FOREIGN KEY (tenant_id, protected_node_id) REFERENCES nodes(tenant_id, id),
    CHECK ((sensitivity = 'STANDARD') OR required_security_level = 'STRONGBOX')
);

-- ─── Policies (§12, DR-POL-7…9) ───────────────────────────────────────────

CREATE TABLE policies (
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    version             bigint NOT NULL,
    epoch               bigint NOT NULL,
    document            jsonb NOT NULL,           -- the policy document
    prev_hash           bytea NOT NULL,           -- hash of previous bundle
    signature           bytea NOT NULL,           -- policy_sig signature
    kid                 text NOT NULL,            -- signing key identifier
    not_before          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,     -- bundles expire 5 min after issuance
    min_daemon_version  text NOT NULL,
    issued_by           uuid REFERENCES users(id),
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version)
);

-- ─── Approval Requests (§11.3, DR-SVC-2…3) ────────────────────────────────

CREATE TABLE approval_requests (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    parent_request_id   uuid,                    -- for multi-device sequential routing
    user_id             uuid NOT NULL,
    device_id           uuid,                    -- target approver device
    node_id             uuid NOT NULL,           -- requesting protected node
    src_node_id         text NOT NULL,           -- initiating Tailscale node
    requesting_ip       inet,
    resource_id         uuid NOT NULL,
    protocol            text NOT NULL,
    ssh_account         text,
    scope               text NOT NULL CHECK (scope IN ('REQUEST', 'CONNECTION', 'DURATION', 'SESSION')),
    binding             jsonb NOT NULL,          -- CBOR-encoded ScopeBinding
    challenge           bytea NOT NULL,          -- single-use server nonce (32 bytes)
    envelope            bytea NOT NULL,          -- COSE_Sign1 serialized RequestEnvelope
    envelope_sig        bytea NOT NULL,          -- detached signature
    policy_version      bigint NOT NULL,
    rule_id             text,
    state               text NOT NULL DEFAULT 'PENDING'
                        CHECK (state IN ('PENDING', 'APPROVED', 'GRANTED', 'DENIED', 'EXPIRED', 'CANCELLED')),
    state_version       int NOT NULL DEFAULT 0,  -- for optimistic concurrency
    response_decision   text,                    -- 'APPROVE' or 'DENY'
    response_sig        bytea,                   -- approval_auth or device_auth signature
    response_key_id     text,
    device_counter      bigint,
    response_nonce      bytea,
    channel_binding     bytea,
    poll_cap_hash       bytea,                   -- SHA-256 of poll capability (hashed at rest)
    redeem_cap_hash     bytea,                   -- SHA-256 of redeem capability (hashed at rest)
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,    -- request TTL (default 60s)
    decided_at          timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
    FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id),
    FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id),
    FOREIGN KEY (tenant_id, parent_request_id) REFERENCES approval_requests(tenant_id, id)
);

-- ─── Grants (§9.3, DR-GRANT-1…3) ──────────────────────────────────────────

CREATE TABLE grants (
    jti                     uuid NOT NULL,
    tenant_id               uuid NOT NULL REFERENCES tenants(id),
    request_id              uuid NOT NULL,
    user_id                 uuid NOT NULL,
    src_node_id             text NOT NULL,
    src_node_key_epoch      bigint NOT NULL,
    device_id               uuid NOT NULL,
    node_id                 uuid NOT NULL,
    resource_id             uuid NOT NULL,
    protocol                text NOT NULL,
    scope                   text NOT NULL,
    binding                 jsonb NOT NULL,
    policy_version          bigint NOT NULL,
    authz_epoch             bigint NOT NULL,
    device_security_level   text NOT NULL,
    agt_bytes               bytea NOT NULL,       -- COSE_Sign1 serialized AGT
    kid                     text NOT NULL,         -- grant_sig key id
    iat                     timestamptz NOT NULL,
    nbf                     timestamptz NOT NULL,
    expires_at              timestamptz NOT NULL,
    consumed_at             timestamptz,           -- set atomically on first use
    PRIMARY KEY (tenant_id, jti),
    UNIQUE (tenant_id, request_id),                -- exactly one grant per request
    FOREIGN KEY (tenant_id, request_id) REFERENCES approval_requests(tenant_id, id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
    FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id),
    FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id)
);

-- ─── Active Sessions (§13, DR-REV-3) ──────────────────────────────────────

CREATE TABLE active_sessions (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           uuid NOT NULL,
    grant_jti           uuid NOT NULL,
    device_id           uuid NOT NULL,
    node_id             uuid NOT NULL,
    session_id          text,
    connection_id       text,
    opened_at           timestamptz NOT NULL DEFAULT now(),
    closed_at           timestamptz,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, grant_jti) REFERENCES grants(tenant_id, jti),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id),
    FOREIGN KEY (tenant_id, node_id) REFERENCES nodes(tenant_id, id),
    CHECK ((session_id IS NULL) <> (connection_id IS NULL)) -- exactly one of session or connection
);

-- ─── Revocations (§13, DR-REV-1…5) ────────────────────────────────────────

CREATE TABLE revocations (
    tenant_id   uuid NOT NULL,
    seq         bigint NOT NULL,                  -- ordered per-tenant stream
    kind        text NOT NULL CHECK (kind IN (
                    'user', 'source_node', 'protected_node',
                    'device', 'key', 'cert', 'grant', 'policy'
                )),
    target      text NOT NULL,                    -- the revoked entity identifier
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, seq)
);

-- ─── Outbox (§11.5, DR-SVC-5…6) ──────────────────────────────────────────

CREATE TABLE outbox (
    tenant_id   uuid NOT NULL,
    seq         bigint NOT NULL,
    consumer    text NOT NULL,                    -- daemon node id or device id
    message_id  uuid NOT NULL,                    -- stable deduplication key
    payload     bytea NOT NULL,                   -- serialized message
    acked_at    timestamptz,                      -- null until acknowledged
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, consumer, seq),
    UNIQUE (tenant_id, message_id)
);

-- ─── Inbox (§11.5, DR-SVC-5…6) ────────────────────────────────────────────

CREATE TABLE inbox (
    tenant_id   uuid NOT NULL,
    consumer    text NOT NULL,
    message_id  uuid NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, consumer, message_id)
);

-- ─── Consumer Cursors (§11.2, DR-SVC-1) ───────────────────────────────────

CREATE TABLE consumer_cursors (
    tenant_id       uuid NOT NULL,
    consumer        text NOT NULL,
    last_acked_seq  bigint NOT NULL DEFAULT 0,
    lease_owner     uuid,                         -- current instance holding the lease
    lease_fence     bigint NOT NULL DEFAULT 0,    -- monotonically increasing fencing token
    lease_expires_at timestamptz,
    PRIMARY KEY (tenant_id, consumer)
);

-- ─── Audit Heads (§16.1, DR-AUD-1…2) ───────────────────────────────────────

CREATE TABLE audit_heads (
    tenant_id   uuid PRIMARY KEY REFERENCES tenants(id),
    last_seq    bigint NOT NULL DEFAULT 0,
    last_hash   bytea NOT NULL
);

-- ─── Audit Events (§16.1, DR-AUD-1…4) ─────────────────────────────────────

CREATE TABLE audit_events (
    tenant_id           uuid NOT NULL,
    seq                 bigint NOT NULL,           -- tenant-local, allocated under advisory lock
    event_type          text NOT NULL,
    producer            text NOT NULL CHECK (producer IN ('service', 'daemon')),
    producer_seq        bigint,                    -- daemon-reported sequence number
    user_id             uuid,
    device_id           uuid,
    src_node_id         text,
    node_id             uuid,
    resource_id         uuid,
    protocol            text,
    result              text,
    request_id          uuid,
    rule_id             text,
    policy_version      bigint,
    correlation_id      uuid,
    payload             jsonb,                     -- event-specific details
    occurred_at         timestamptz NOT NULL DEFAULT now(),
    prev_hash           bytea NOT NULL,            -- previous event's row_hash
    row_hash            bytea NOT NULL,            -- SHA-256 of this event row
    producer_signature  bytea,                     -- daemon mTLS-key signature for daemon events
    PRIMARY KEY (tenant_id, seq)
);

-- ─── Inventory Snapshots (§12.2, DR-POL-6a) ───────────────────────────────

CREATE TABLE inventory_snapshots (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    tailnet_id      text NOT NULL,
    snapshot_data   jsonb NOT NULL,                -- nodes, users, tags, groups, services
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

-- ─── Break-Glass Authorizations (§19.2, DR-BG-1) ──────────────────────────

CREATE TABLE breakglass_authorizations (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    user_id             uuid NOT NULL,
    src_node_id         text NOT NULL,
    resource_id         uuid NOT NULL,
    protocol            text NOT NULL,
    reason              text NOT NULL,
    incident_id         text NOT NULL,
    custodian_sigs      jsonb NOT NULL,            -- 2-of-3 FIDO2 signatures
    authorization       bytea NOT NULL,            -- COSE_Sign1 signed authorization
    expires_at          timestamptz NOT NULL,      -- max 15 minutes
    used_at             timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id),
    FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id)
);

-- ─── Indexes ───────────────────────────────────────────────────────────────

-- Approval requests by state for efficient scanning
CREATE INDEX idx_approval_requests_state ON approval_requests(tenant_id, state) WHERE state = 'PENDING';

-- Approval requests by device for device-specific queries
CREATE INDEX idx_approval_requests_device ON approval_requests(tenant_id, device_id);

-- Grants by user/device for revocation queries
CREATE INDEX idx_grants_user_device ON grants(tenant_id, user_id, device_id);
CREATE INDEX idx_grants_src_node ON grants(tenant_id, src_node_id);

-- Active sessions by device for revocation kill
CREATE INDEX idx_active_sessions_device ON active_sessions(tenant_id, device_id) WHERE closed_at IS NULL;
CREATE INDEX idx_active_sessions_grant ON active_sessions(tenant_id, grant_jti);

-- Revocations by creation time
CREATE INDEX idx_revocations_created ON revocations(tenant_id, created_at DESC);

-- Outbox by acked status
CREATE INDEX idx_outbox_unacked ON outbox(tenant_id, consumer) WHERE acked_at IS NULL;

-- Audit events by time for search
CREATE INDEX idx_audit_events_time ON audit_events(tenant_id, occurred_at DESC);
CREATE INDEX idx_audit_events_type ON audit_events(tenant_id, event_type, occurred_at DESC);
CREATE INDEX idx_audit_events_user ON audit_events(tenant_id, user_id, occurred_at DESC);
CREATE INDEX idx_audit_events_request ON audit_events(tenant_id, request_id);

-- ─── Row-Level Security ───────────────────────────────────────────────────

-- Enable RLS on all tenant-scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE active_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumer_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE breakglass_authorizations ENABLE ROW LEVEL SECURITY;

-- RLS policy: application role sees only its current tenant
-- The application sets app.current_tenant_id before queries via SET LOCAL
CREATE FUNCTION app_current_tenant() RETURNS uuid AS $$
BEGIN
    RETURN current_setting('app.current_tenant_id', true)::uuid;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create reusable RLS policy for tenant-scoped access
CREATE FUNCTION create_tenant_rls_policy(table_name text) RETURNS void AS $$
BEGIN
    EXECUTE format('
        CREATE POLICY tenant_isolation ON %I
        FOR ALL
        USING (tenant_id = app_current_tenant())
        WITH CHECK (tenant_id = app_current_tenant())
    ', table_name);
END;
$$ LANGUAGE plpgsql;

-- Apply RLS to all tenant-scoped tables
SELECT create_tenant_rls_policy('users');
SELECT create_tenant_rls_policy('identity_links');
SELECT create_tenant_rls_policy('devices');
SELECT create_tenant_rls_policy('nodes');
SELECT create_tenant_rls_policy('resources');
SELECT create_tenant_rls_policy('policies');
SELECT create_tenant_rls_policy('approval_requests');
SELECT create_tenant_rls_policy('grants');
SELECT create_tenant_rls_policy('active_sessions');
SELECT create_tenant_rls_policy('revocations');
SELECT create_tenant_rls_policy('outbox');
SELECT create_tenant_rls_policy('inbox');
SELECT create_tenant_rls_policy('consumer_cursors');
SELECT create_tenant_rls_policy('audit_events');
SELECT create_tenant_rls_policy('inventory_snapshots');
SELECT create_tenant_rls_policy('breakglass_authorizations');

-- ─── State Transition Functions ────────────────────────────────────────────

-- Transition approval request state with validation
CREATE FUNCTION transition_approval_request(
    p_tenant_id uuid,
    p_request_id uuid,
    p_new_state text,
    p_expected_version int
) RETURNS boolean AS $$
DECLARE
    v_current_state text;
    v_current_version int;
    v_valid boolean;
BEGIN
    SELECT state, state_version
    INTO v_current_state, v_current_version
    FROM approval_requests
    WHERE tenant_id = p_tenant_id AND id = p_request_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Request not found';
    END IF;

    -- Optimistic concurrency check
    IF v_current_version != p_expected_version THEN
        RAISE EXCEPTION 'State version conflict: expected %, got %', p_expected_version, v_current_version;
    END IF;

    -- Validate transition
    v_valid := false;

    IF v_current_state = 'PENDING' AND p_new_state IN ('APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED') THEN
        v_valid := true;
    ELSIF v_current_state = 'APPROVED' AND p_new_state = 'GRANTED' THEN
        v_valid := true;
    END IF;

    IF NOT v_valid THEN
        RAISE EXCEPTION 'Invalid state transition: % -> %', v_current_state, p_new_state;
    END IF;

    -- Execute transition
    UPDATE approval_requests
    SET state = p_new_state,
        state_version = v_current_version + 1,
        decided_at = CASE WHEN p_new_state IN ('APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED')
                          THEN now() ELSE decided_at END
    WHERE tenant_id = p_tenant_id AND id = p_request_id;

    RETURN true;
END;
$$ LANGUAGE plpgsql;

-- Atomically consume a single-use grant (DR-GRANT-6)
CREATE FUNCTION consume_grant(
    p_tenant_id uuid,
    p_jti uuid,
    p_now timestamptz
) RETURNS boolean AS $$
DECLARE
    v_consumed_at timestamptz;
    v_expires_at timestamptz;
BEGIN
    SELECT consumed_at, expires_at
    INTO v_consumed_at, v_expires_at
    FROM grants
    WHERE tenant_id = p_tenant_id AND jti = p_jti
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    IF v_consumed_at IS NOT NULL THEN
        RETURN false; -- Already consumed
    END IF;

    IF p_now > v_expires_at THEN
        RETURN false; -- Expired
    END IF;

    -- Atomic consume
    UPDATE grants
    SET consumed_at = p_now
    WHERE tenant_id = p_tenant_id AND jti = p_jti
      AND consumed_at IS NULL;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Atomically advance device counter (DR-SIG-6)
CREATE FUNCTION advance_device_counter(
    p_tenant_id uuid,
    p_device_id uuid,
    p_received_counter bigint
) RETURNS boolean AS $$
BEGIN
    UPDATE devices
    SET counter = p_received_counter
    WHERE tenant_id = p_tenant_id
      AND id = p_device_id
      AND counter < p_received_counter;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Acquire advisory lock for per-tenant audit insertion (DR-AUD-1)
CREATE FUNCTION insert_audit_event(
    p_tenant_id uuid,
    p_event_type text,
    p_producer text,
    p_data jsonb
) RETURNS bigint AS $$
DECLARE
    v_last_seq bigint;
    v_last_hash bytea;
    v_new_seq bigint;
    v_row_hash bytea;
BEGIN
    -- Acquire tenant-scoped advisory lock
    PERFORM pg_advisory_xact_lock(hashtext('audit_' || p_tenant_id::text));

    -- Get current audit head
    SELECT last_seq, last_hash INTO v_last_seq, v_last_hash
    FROM audit_heads
    WHERE tenant_id = p_tenant_id;

    IF NOT FOUND THEN
        -- Initialize audit head for tenant
        v_last_seq := 0;
        v_last_hash := '\x00'::bytea;
        INSERT INTO audit_heads (tenant_id, last_seq, last_hash)
        VALUES (p_tenant_id, v_last_seq, v_last_hash);
    END IF;

    v_new_seq := v_last_seq + 1;

    -- Compute row hash: SHA-256(prev_hash || seq || event_type || occurred_at)
    v_row_hash := digest(
        v_last_hash ||
        int8send(v_new_seq) ||
        p_event_type::bytea ||
        extract(epoch from now())::text::bytea,
        'sha256'
    );

    -- Insert event
    INSERT INTO audit_events (
        tenant_id, seq, event_type, producer,
        payload, prev_hash, row_hash
    ) VALUES (
        p_tenant_id, v_new_seq, p_event_type, p_producer,
        p_data, v_last_hash, v_row_hash
    );

    -- Advance head
    UPDATE audit_heads
    SET last_seq = v_new_seq, last_hash = v_row_hash
    WHERE tenant_id = p_tenant_id;

    RETURN v_new_seq;
END;
$$ LANGUAGE plpgsql;

-- ─── Validation Triggers ───────────────────────────────────────────────────

-- Ensure grant expires_at respects scope/sensitivity caps
CREATE FUNCTION validate_grant_ttl() RETURNS trigger AS $$
DECLARE
    v_sensitivity text;
    v_max_seconds int;
BEGIN
    SELECT sensitivity INTO v_sensitivity
    FROM resources
    WHERE tenant_id = NEW.tenant_id AND id = NEW.resource_id;

    -- Compute max TTL based on scope and sensitivity
    CASE NEW.scope
        WHEN 'REQUEST'  THEN v_max_seconds := 30;
        WHEN 'CONNECTION' THEN v_max_seconds := 120;
        WHEN 'DURATION' THEN
            CASE v_sensitivity
                WHEN 'STANDARD' THEN v_max_seconds := 900;  -- 15 min
                WHEN 'HIGH'     THEN v_max_seconds := 300;  -- 5 min
                WHEN 'ADMIN'    THEN v_max_seconds := 0;    -- prohibited
                ELSE v_max_seconds := 0;
            END CASE;
        WHEN 'SESSION' THEN
            CASE v_sensitivity
                WHEN 'STANDARD' THEN v_max_seconds := 28800; -- 8 hours
                WHEN 'HIGH'     THEN v_max_seconds := 3600;  -- 1 hour
                WHEN 'ADMIN'    THEN v_max_seconds := 1800;  -- 30 min
                ELSE v_max_seconds := 0;
            END CASE;
        ELSE v_max_seconds := 0;
    END CASE;

    IF v_max_seconds = 0 THEN
        RAISE EXCEPTION 'DURATION scope prohibited for ADMIN sensitivity';
    END IF;

    IF EXTRACT(epoch FROM (NEW.expires_at - NEW.iat)) > v_max_seconds THEN
        RAISE EXCEPTION 'Grant TTL exceeds maximum for scope % / sensitivity %', NEW.scope, v_sensitivity;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_validate_grant_ttl
    BEFORE INSERT ON grants
    FOR EACH ROW EXECUTE FUNCTION validate_grant_ttl();

-- ─── Tenant Bootstrap Helper ──────────────────────────────────────────────

CREATE FUNCTION bootstrap_tenant(p_tenant_name text) RETURNS uuid AS $$
DECLARE
    v_tenant_id uuid;
BEGIN
    INSERT INTO tenants (id, name) VALUES (uuid_generate_v7(), p_tenant_name)
    RETURNING id INTO v_tenant_id;

    -- Initialize audit head
    INSERT INTO audit_heads (tenant_id, last_seq, last_hash)
    VALUES (v_tenant_id, 0, '\x00'::bytea);

    RETURN v_tenant_id;
END;
$$ LANGUAGE plpgsql;

COMMIT;
