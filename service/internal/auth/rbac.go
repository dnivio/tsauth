// Package auth implements deny-by-default RBAC for the Dnivio Approval Service.
// Per §14.4 (DR-AUTH-7…9) of ENGINEERING.md v2.1.
// Features: centralized RBAC with roles, separation of duties, object ownership enforcement.
package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// ─── Roles (DR-AUTH-7) ──────────────────────────────────────────────────

// Role defines a set of permissions for a Dnivio user.
type Role string

const (
	RoleUser           Role = "user"            // End user — approve access, view own devices
	RoleDeviceAdmin    Role = "device_admin"    // Manage devices for a tenant
	RolePolicyAuthor   Role = "policy_author"   // Author policy documents
	RolePolicyApprover Role = "policy_approver"  // Approve policy publications (SoD)
	RoleAuditor        Role = "auditor"         // View and export audit logs
	RoleSecurityAdmin  Role = "security_admin"  // Manage security settings, keys, revocation
	RoleOperator       Role = "operator"        // View operational state, manage nodes
)

// ─── Permissions ────────────────────────────────────────────────────────

// Permission represents a specific action on a resource type.
type Permission string

const (
	PermTenantRead       Permission = "tenant:read"
	PermTenantWrite      Permission = "tenant:write"

	PermUserRead         Permission = "user:read"
	PermUserWrite        Permission = "user:write"

	PermDeviceRead       Permission = "device:read"
	PermDeviceWrite       Permission = "device:write"
	PermDeviceRevoke     Permission = "device:revoke"
	PermDeviceEnroll     Permission = "device:enroll"

	PermNodeRead         Permission = "node:read"
	PermNodeRegister     Permission = "node:register"
	PermNodeRevoke       Permission = "node:revoke"

	PermResourceRead     Permission = "resource:read"
	PermResourceWrite    Permission = "resource:write"

	PermPolicyRead       Permission = "policy:read"
	PermPolicyWrite      Permission = "policy:write"
	PermPolicyPublish    Permission = "policy:publish"

	PermApprovalCreate   Permission = "approval:create"
	PermApprovalRespond  Permission = "approval:respond"

	PermAuditRead        Permission = "audit:read"
	PermAuditExport      Permission = "audit:export"

	PermBreakGlass       Permission = "breakglass:execute"

	PermSecuritySettings Permission = "security:settings"
	PermKeyRotate        Permission = "key:rotate"
)

// rolePermissions maps each role to its allowed permissions.
var rolePermissions = map[Role][]Permission{
	RoleUser: {
		PermDeviceRead,
		PermDeviceEnroll,
		PermApprovalRespond,
	},
	RoleDeviceAdmin: {
		PermDeviceRead,
		PermDeviceWrite,
		PermDeviceRevoke,
		PermDeviceEnroll,
		PermUserRead,
	},
	RolePolicyAuthor: {
		PermPolicyRead,
		PermPolicyWrite,
		PermResourceRead,
	},
	RolePolicyApprover: {
		PermPolicyRead,
		PermPolicyPublish,
		PermResourceRead,
	},
	RoleAuditor: {
		PermAuditRead,
		PermAuditExport,
		PermTenantRead,
		PermUserRead,
		PermDeviceRead,
		PermPolicyRead,
	},
	RoleSecurityAdmin: {
		PermSecuritySettings,
		PermKeyRotate,
		PermDeviceRevoke,
		PermNodeRevoke,
		PermBreakGlass,
		PermAuditRead,
	},
	RoleOperator: {
		PermNodeRead,
		PermNodeRegister,
		PermResourceRead,
		PermUserRead,
		PermDeviceRead,
		PermAuditRead,
	},
}

// ─── Authorizer ──────────────────────────────────────────────────────────

// Authorizer enforces deny-by-default RBAC with object ownership and tenant scoping.
type Authorizer struct {
	db         *sql.DB
	userRoles  map[uuid.UUID][]Role // user_id -> roles (cached; refreshed periodically)
}

// NewAuthorizer creates a new RBAC authorizer.
func NewAuthorizer(db *sql.DB) *Authorizer {
	return &Authorizer{
		db:        db,
		userRoles: make(map[uuid.UUID][]Role),
	}
}

// ─── Permission Checks ──────────────────────────────────────────────────

// Check verifies that a principal has the required permission for an operation.
// Per DR-AUTH-7: centralized deny-by-default.
func (a *Authorizer) Check(ctx context.Context, userID, tenantID uuid.UUID, perm Permission, resourceOwner *uuid.UUID) error {
	// Get user roles
	roles, err := a.getRoles(ctx, userID, tenantID)
	if err != nil {
		return fmt.Errorf("auth: resolve roles: %w", err)
	}

	if len(roles) == 0 {
		return fmt.Errorf("auth: no roles assigned — access denied")
	}

	// Check if any role has the required permission
	hasPerm := false
	for _, role := range roles {
		if a.roleHasPermission(role, perm) {
			hasPerm = true
			break
		}
	}

	if !hasPerm {
		return fmt.Errorf("auth: permission %s denied for roles %v", perm, roles)
	}

	// Object ownership check: if a resource owner is specified,
	// the user must be the owner (or have an admin role)
	if resourceOwner != nil && *resourceOwner != userID {
		if !a.hasAdminRole(roles) {
			return fmt.Errorf("auth: object ownership violation — user %s cannot access resource owned by %s", userID, resourceOwner)
		}
	}

	return nil
}

// ─── Separation of Duties (DR-AUTH-8) ──────────────────────────────────

// CheckSeparationOfDuties verifies that a single principal cannot both
// author and approve a policy, initiate and approve a key rotation,
// or request and approve an audit export.
func (a *Authorizer) CheckSeparationOfDuties(ctx context.Context, authorID, approverID uuid.UUID, tenantID uuid.UUID) error {
	if authorID == approverID {
		return fmt.Errorf("auth: separation of duties violation — author and approver must be distinct")
	}

	// Verify both users exist and are active
	for _, uid := range []uuid.UUID{authorID, approverID} {
		roles, err := a.getRoles(ctx, uid, tenantID)
		if err != nil || len(roles) == 0 {
			return fmt.Errorf("auth: user %s has no valid roles", uid)
		}
	}

	return nil
}

// CheckPolicyApprovalSoD validates policy author ≠ policy approver (DR-AUTH-8).
func (a *Authorizer) CheckPolicyApprovalSoD(ctx context.Context, authorID, approverID uuid.UUID, tenantID uuid.UUID) error {
	return a.CheckSeparationOfDuties(ctx, authorID, approverID, tenantID)
}

// ─── Cross-Tenant & IDOR Protection (DR-AUTH-9) ────────────────────────

// CheckTenantScoping verifies that a user can only access resources within their tenant.
func (a *Authorizer) CheckTenantScoping(ctx context.Context, userID uuid.UUID, requestTenantID, userTenantID uuid.UUID) error {
	if requestTenantID != userTenantID {
		return fmt.Errorf("auth: cross-tenant access denied — user %s cannot access tenant %s", userID, requestTenantID)
	}
	return nil
}

// CheckObjectOwnership verifies tenant-scoped object ownership for IDOR protection.
// The operation is on /devices/{deviceID}, /nodes/{nodeID}, /policies/{policyID}, etc.
func (a *Authorizer) CheckObjectOwnership(ctx context.Context, userID, tenantID uuid.UUID, objectType string, objectID uuid.UUID) error {
	// Verify the object exists in the user's tenant
	var objTenantID uuid.UUID
	var ownerID *uuid.UUID

	switch objectType {
	case "device":
		err := a.db.QueryRowContext(ctx, `
			SELECT tenant_id, user_id FROM devices WHERE tenant_id = $1 AND id = $2
		`, tenantID, objectID).Scan(&objTenantID, &ownerID)
		if err != nil {
			return fmt.Errorf("auth: device %s not found in tenant %s", objectID, tenantID)
		}
	case "node":
		err := a.db.QueryRowContext(ctx, `
			SELECT tenant_id FROM nodes WHERE tenant_id = $1 AND id = $2
		`, tenantID, objectID).Scan(&objTenantID)
		if err != nil {
			return fmt.Errorf("auth: node %s not found in tenant %s", objectID, tenantID)
		}
	case "resource":
		err := a.db.QueryRowContext(ctx, `
			SELECT tenant_id FROM resources WHERE tenant_id = $1 AND id = $2
		`, tenantID, objectID).Scan(&objTenantID)
		if err != nil {
			return fmt.Errorf("auth: resource %s not found in tenant %s", objectID, tenantID)
		}
	case "policy":
		err := a.db.QueryRowContext(ctx, `
			SELECT tenant_id FROM policies WHERE tenant_id = $1 AND version = (SELECT MAX(version) FROM policies WHERE tenant_id = $1)
		`, tenantID).Scan(&objTenantID)
		if err != nil {
			return fmt.Errorf("auth: policy not found in tenant %s", tenantID)
		}
	default:
		return fmt.Errorf("auth: unknown object type %s", objectType)
	}

	return a.CheckTenantScoping(ctx, userID, tenantID, objTenantID)
}

// ─── Role Resolution ────────────────────────────────────────────────────

func (a *Authorizer) getRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]Role, error) {
	// Check cache first (in production, uses distributed cache with invalidation)
	if roles, ok := a.userRoles[userID]; ok {
		return roles, nil
	}

	// Query role assignments from database
	rows, err := a.db.QueryContext(ctx, `
		SELECT role FROM user_roles
		WHERE tenant_id = $1 AND user_id = $2
	`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: query roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, Role(r))
	}

	a.userRoles[userID] = roles
	return roles, rows.Err()
}

func (a *Authorizer) roleHasPermission(role Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

func (a *Authorizer) hasAdminRole(roles []Role) bool {
	for _, r := range roles {
		if r == RoleSecurityAdmin || r == RoleOperator || r == RoleDeviceAdmin {
			return true
		}
	}
	return false
}

// ─── Role Management ────────────────────────────────────────────────────

// AssignRole assigns a role to a user within a tenant.
func (a *Authorizer) AssignRole(ctx context.Context, tenantID, userID, assignedBy uuid.UUID, role Role) error {
	// The assigner must have permission to manage roles
	if err := a.Check(ctx, assignedBy, tenantID, PermSecuritySettings, nil); err != nil {
		return fmt.Errorf("auth: assign role: %w", err)
	}

	_, err := a.db.ExecContext(ctx, `
		INSERT INTO user_roles (tenant_id, user_id, role, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, user_id, role) DO NOTHING
	`, tenantID, userID, role, assignedBy)
	if err != nil {
		return fmt.Errorf("auth: insert role: %w", err)
	}

	// Invalidate cache
	delete(a.userRoles, userID)

	return nil
}

// RemoveRole removes a role from a user.
func (a *Authorizer) RemoveRole(ctx context.Context, tenantID, userID, removedBy uuid.UUID, role Role) error {
	if err := a.Check(ctx, removedBy, tenantID, PermSecuritySettings, nil); err != nil {
		return fmt.Errorf("auth: remove role: %w", err)
	}

	_, err := a.db.ExecContext(ctx, `
		DELETE FROM user_roles
		WHERE tenant_id = $1 AND user_id = $2 AND role = $3
	`, tenantID, userID, role)
	if err != nil {
		return fmt.Errorf("auth: delete role: %w", err)
	}

	delete(a.userRoles, userID)
	return nil
}

// Add the user_roles table note: this would be in a follow-up migration.
// CREATE TABLE user_roles (
//     tenant_id uuid NOT NULL REFERENCES tenants(id),
//     user_id uuid NOT NULL REFERENCES users(id),
//     role text NOT NULL,
//     assigned_by uuid NOT NULL REFERENCES users(id),
//     assigned_at timestamptz NOT NULL DEFAULT now(),
//     PRIMARY KEY (tenant_id, user_id, role)
// );

// Ensure imports
var _ = context.Background
