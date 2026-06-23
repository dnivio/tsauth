package auth

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// ─── H4: RBAC cache thread-safety and tenant scoping ────────────────────

// TestRBACCache_ConcurrentAccess verifies the H4 fix: concurrent role reads
// and cache invalidation do not cause data races or panics.
func TestRBACCache_ConcurrentAccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auth := NewAuthorizer(db)
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	// Mock: role query returns PolicyAuthor
	mock.ExpectQuery("SELECT role FROM user_roles").
		WithArgs(tenantID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("policy_author"))

	// Warm cache
	_, err = auth.getRoles(context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("getRoles: %v", err)
	}

	// Concurrent reads and cache invalidations
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Read
			auth.getRoles(context.Background(), userID, tenantID)
			// Invalidate
			auth.mu.Lock()
			delete(auth.userRoles, roleCacheKey{tenantID: tenantID, userID: userID})
			auth.mu.Unlock()
		}()
	}
	wg.Wait()
	// No panic = pass (Go's race detector catches unsynchronized map access)
}

// TestRBACCache_TenantScoping verifies the H4 fix: roles for user A in
// tenant 1 are not returned in tenant 2's context.
func TestRBACCache_TenantScoping(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auth := NewAuthorizer(db)
	userID := uuid.Must(uuid.NewV7())
	tenantA := uuid.Must(uuid.NewV7())
	tenantB := uuid.Must(uuid.NewV7())

	// Mock: tenant A has SecurityAdmin
	mock.ExpectQuery("SELECT role FROM user_roles").
		WithArgs(tenantA, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("security_admin"))

	// Mock: tenant B has only User
	mock.ExpectQuery("SELECT role FROM user_roles").
		WithArgs(tenantB, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))

	// Fetch roles for tenant A
	rolesA, err := auth.getRoles(context.Background(), userID, tenantA)
	if err != nil {
		t.Fatalf("getRoles tenant A: %v", err)
	}
	if len(rolesA) != 1 || rolesA[0] != RoleSecurityAdmin {
		t.Errorf("tenant A should have SecurityAdmin, got %v", rolesA)
	}

	// Fetch roles for tenant B — must NOT return tenant A's cached roles
	rolesB, err := auth.getRoles(context.Background(), userID, tenantB)
	if err != nil {
		t.Fatalf("getRoles tenant B: %v", err)
	}
	if len(rolesB) != 1 || rolesB[0] != RoleUser {
		t.Errorf("tenant B should have User, got %v (H4 cross-tenant leak)", rolesB)
	}
}

// TestRBACCache_TTLExpiry verifies the H4 fix: cached roles expire after TTL.
func TestRBACCache_TTLExpiry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auth := NewAuthorizer(db)
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	// Mock: first call returns PolicyAuthor
	mock.ExpectQuery("SELECT role FROM user_roles").
		WithArgs(tenantID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("policy_author"))

	roles, err := auth.getRoles(context.Background(), userID, tenantID)
	if err != nil || len(roles) != 1 || roles[0] != RolePolicyAuthor {
		t.Fatalf("first getRoles failed: %v, got %v", err, roles)
	}

	// Manually expire the cache entry
	key := roleCacheKey{tenantID: tenantID, userID: userID}
	auth.mu.Lock()
	entry := auth.userRoles[key]
	entry.expires = time.Now().UTC().Add(-1 * time.Second) // expired
	auth.userRoles[key] = entry
	auth.mu.Unlock()

	// Mock: second call (after expiry) returns Operator (role changed)
	mock.ExpectQuery("SELECT role FROM user_roles").
		WithArgs(tenantID, userID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("operator"))

	roles, err = auth.getRoles(context.Background(), userID, tenantID)
	if err != nil || len(roles) != 1 || roles[0] != RoleOperator {
		t.Errorf("after TTL expiry should re-fetch from DB, got %v, err=%v", roles, err)
	}
}

// ─── H5: IDOR protection for policy objects ─────────────────────────────

// TestCheckObjectOwnership_PolicyIDOR verifies the H5 fix: policy ownership
// check validates the specific policy ID, not just any policy in the tenant.
func TestCheckObjectOwnership_PolicyIDOR(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auth := NewAuthorizer(db)
	userID := uuid.Must(uuid.NewV7())
	tenantID := uuid.Must(uuid.NewV7())
	policyID := uuid.Must(uuid.NewV7())
	wrongPolicyID := uuid.Must(uuid.NewV7())

	// Mock: the specific policy exists and belongs to this tenant
	mock.ExpectQuery("SELECT tenant_id FROM policies").
		WithArgs(tenantID, policyID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID))

	err = auth.CheckObjectOwnership(context.Background(), userID, tenantID, "policy", policyID)
	if err != nil {
		t.Errorf("valid policy should pass ownership check: %v", err)
	}

	// With a different policy ID, the DB should return no rows
	mock.ExpectQuery("SELECT tenant_id FROM policies").
		WithArgs(tenantID, wrongPolicyID).
		WillReturnError(sql.ErrNoRows)

	err = auth.CheckObjectOwnership(context.Background(), userID, tenantID, "policy", wrongPolicyID)
	if err == nil {
		t.Fatal("H5 FAIL: non-existent policy ID should be rejected")
	}
}

// TestCheckObjectOwnership_PolicyCrossTenant verifies policies in other tenants are rejected.
func TestCheckObjectOwnership_PolicyCrossTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	auth := NewAuthorizer(db)
	userID := uuid.Must(uuid.NewV7())
	tenantA := uuid.Must(uuid.NewV7())
	
	policyID := uuid.Must(uuid.NewV7())

	// Policy exists in tenant B (different from requested tenant A)
	mock.ExpectQuery("SELECT tenant_id FROM policies").
		WithArgs(tenantA, policyID).
		WillReturnError(sql.ErrNoRows)

	err = auth.CheckObjectOwnership(context.Background(), userID, tenantA, "policy", policyID)
	if err == nil {
		t.Fatal("H5 FAIL: cross-tenant policy access should be rejected")
	}
}
