-- Dnivio Approval Service — Rollback migration
-- Migration: 001_initial_schema.down

BEGIN;

-- Drop triggers
DROP TRIGGER IF EXISTS trg_validate_grant_ttl ON grants;

-- Drop functions
DROP FUNCTION IF EXISTS bootstrap_tenant(text);
DROP FUNCTION IF EXISTS insert_audit_event(uuid, text, text, jsonb);
DROP FUNCTION IF EXISTS advance_device_counter(uuid, uuid, bigint);
DROP FUNCTION IF EXISTS consume_grant(uuid, uuid, timestamptz);
DROP FUNCTION IF EXISTS transition_approval_request(uuid, uuid, text, int);
DROP FUNCTION IF EXISTS create_tenant_rls_policy(text);
DROP FUNCTION IF EXISTS app_current_tenant();

-- Drop tables (order respects FK dependencies)
DROP TABLE IF EXISTS breakglass_authorizations;
DROP TABLE IF EXISTS inventory_snapshots;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS audit_heads;
DROP TABLE IF EXISTS consumer_cursors;
DROP TABLE IF EXISTS inbox;
DROP TABLE IF EXISTS outbox;
DROP TABLE IF EXISTS revocations;
DROP TABLE IF EXISTS active_sessions;
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS approval_requests;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS identity_links;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

COMMIT;
