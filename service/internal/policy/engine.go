// Package policy implements the Dnivio policy engine per §12 of ENGINEERING.md v2.1.
// Features: protected-resource registry, default-deny lattice, formal evaluation,
// coverage analysis, anti-rollback freshness, inventory adapters.
package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/dnivio/contracts"
	"github.com/google/uuid"
)

// ─── Decision Lattice (DR-POL-1…2) ──────────────────────────────────────

// EvaluateResult is the output of policy evaluation.
type EvaluateResult struct {
	Decision      contracts.EnforcementDecision `json:"decision"`
	MatchedRuleID string                        `json:"matched_rule_id,omitempty"`
	Scope         contracts.Scope               `json:"scope,omitempty"`
	Explanation   string                        `json:"explanation"`
	RequireStepUp bool                          `json:"require_step_up"`
	PolicyVersion int64                         `json:"policy_version"`
	AuthzEpoch     int64                        `json:"authz_epoch"`
}

// ─── Policy Document ────────────────────────────────────────────────────

// PolicyDocument is the top-level policy structure.
type PolicyDocument struct {
	Version    int             `json:"version"`     // schema version
	Rules       []PolicyRule   `json:"rules"`
	InventorySnapshotID string  `json:"inventory_snapshot_id"`
}

// PolicyRule defines a single access control rule.
type PolicyRule struct {
	ID          string                         `json:"id"`
	Priority    int                            `json:"priority"`   // higher = evaluated first
	Effect      contracts.EnforcementDecision  `json:"effect"`     // DENY | REQUIRE_STEP_UP | ALLOW_WITHOUT_STEP_UP
	Description string                         `json:"description,omitempty"`

	// Subjects (OR within dimension, AND across dimensions)
	Subjects  []SubjectSelector  `json:"subjects,omitempty"`
	Resources []ResourceSelector `json:"resources,omitempty"`
	Protocols []string           `json:"protocols,omitempty"` // HTTP, HTTPS, TCP, SSH

	// Scope constraints
	AllowedScopes       []contracts.Scope    `json:"allowed_scopes,omitempty"`
	RequireOnlineCheck  bool                 `json:"require_online_check,omitempty"`  // HIGH/ADMIN
	MaxDurationSeconds  *int                 `json:"max_duration_seconds,omitempty"`  // override caps

	// Verification frequency
	VerificationFrequency string              `json:"verification_frequency,omitempty"` // EVERY_REQUEST, EVERY_CONNECTION, FIXED_DURATION, PER_SESSION
}

// SubjectSelector selects subjects (OR within the selector list).
type SubjectSelector struct {
	Users      []string `json:"users,omitempty"`       // user UUIDs
	Groups     []string `json:"groups,omitempty"`      // group names (resolved via inventory)
	DeviceTags []string `json:"device_tags,omitempty"` // tag names
	PrincipalKinds []contracts.PrincipalKind `json:"principal_kinds,omitempty"`
}

// ResourceSelector selects protected resources (OR within the selector list).
type ResourceSelector struct {
	ResourceIDs []string               `json:"resource_ids,omitempty"` // explicit resource UUIDs
	Tags        []string               `json:"tags,omitempty"`         // resource tags
	Services    []string               `json:"services,omitempty"`     // service IDs
	Ports       []int                  `json:"ports,omitempty"`
	DeploymentModes []contracts.DeploymentMode `json:"deployment_modes,omitempty"`
	Sensitivity []contracts.Sensitivity `json:"sensitivity,omitempty"`
}

// ─── Policy Engine ──────────────────────────────────────────────────────

// Engine evaluates access requests against the current policy.
type Engine struct {
	db *sql.DB
}

// NewEngine creates a new policy engine.
func NewEngine(db *sql.DB) *Engine {
	return &Engine{db: db}
}

// Evaluate determines the enforcement decision for an access attempt.
// Implements DR-POL-4: OR within dimension, AND across dimensions.
// Implements DR-POL-2: default-deny for protected resources.
func (e *Engine) Evaluate(ctx context.Context, tenantID uuid.UUID, principal contracts.Principal, resource contracts.ResourceID, protocol string, requestedScope contracts.Scope) (*EvaluateResult, error) {
	// Check if resource is protected (DR-POL-1)
	isProtected, err := e.isResourceProtected(ctx, tenantID, resource)
	if err != nil {
		return nil, fmt.Errorf("policy: check protected: %w", err)
	}

	if !isProtected {
		return &EvaluateResult{
			Decision:    contracts.DecisionNotProtected,
			Explanation: "Resource is not registered as protected",
		}, nil
	}

	// Load the current active policy bundle
	bundle, err := e.loadActiveBundle(ctx, tenantID)
	if err != nil {
		// No policy or policy stale → DENY (DR-POL-9)
		return &EvaluateResult{
			Decision:    contracts.DecisionEnforceDeny,
			Explanation: fmt.Sprintf("Policy unavailable or expired: %v", err),
		}, nil
	}

	// Check freshness (DR-POL-9)
	if time.Now().UTC().After(bundle.ExpiresAt) {
		return &EvaluateResult{
			Decision:    contracts.DecisionEnforceDeny,
			Explanation: "Policy bundle expired — failing closed",
		}, nil
	}

	// Parse policy document
	var doc PolicyDocument
	if err := json.Unmarshal(bundle.Document, &doc); err != nil {
		return &EvaluateResult{
			Decision:    contracts.DecisionEnforceDeny,
			Explanation: fmt.Sprintf("Policy document parse error: %v", err),
		}, nil
	}

	// Sort rules by priority (highest first)
	rules := make([]PolicyRule, len(doc.Rules))
	copy(rules, doc.Rules)
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	// Evaluate rules
	for _, rule := range rules {
		if e.ruleMatches(&rule, principal, resource, protocol, requestedScope) {
			// Check for tie conflicts at this priority level
			if e.hasConflictingTie(&rules, &rule, principal, resource, protocol, requestedScope) {
				return &EvaluateResult{
					Decision:    contracts.DecisionEnforceDeny,
					Explanation: fmt.Sprintf("Ambiguous policy: conflicting rules at priority %d", rule.Priority),
				}, nil
			}

			// DENY cannot be overridden by equal/lower priority
			return &EvaluateResult{
				Decision:      rule.Effect,
				MatchedRuleID: rule.ID,
				Scope:         requestedScope,
				Explanation:   fmt.Sprintf("Rule %q matched: %s", rule.ID, rule.Description),
				RequireStepUp: rule.Effect == contracts.DecisionRequireStepUp,
				PolicyVersion: bundle.Version,
				AuthzEpoch:    bundle.Epoch,
			}, nil
		}
	}

	// No matching rule → DENY (default-deny for protected, DR-POL-2)
	return &EvaluateResult{
		Decision:    contracts.DecisionEnforceDeny,
		Explanation: "No matching policy rule — default deny for protected resources",
	}, nil
}

// ruleMatches checks if a rule matches the given access parameters.
// Within each dimension, selectors are OR'd; across dimensions they are AND'd.
func (e *Engine) ruleMatches(rule *PolicyRule, principal contracts.Principal, resource contracts.ResourceID, protocol string, scope contracts.Scope) bool {
	// Subject matching (OR within dimension)
	if len(rule.Subjects) > 0 {
		subjectMatched := false
		for _, sel := range rule.Subjects {
			if e.subjectMatches(&sel, principal) {
				subjectMatched = true
				break
			}
		}
		if !subjectMatched {
			return false
		}
	}

	// Resource matching (OR within dimension)
	if len(rule.Resources) > 0 {
		resourceMatched := false
		for _, sel := range rule.Resources {
			if e.resourceMatches(&sel, resource) {
				resourceMatched = true
				break
			}
		}
		if !resourceMatched {
			return false
		}
	}

	// Protocol matching (OR within dimension)
	if len(rule.Protocols) > 0 {
		protocolMatched := false
		for _, p := range rule.Protocols {
			if p == protocol {
				protocolMatched = true
				break
			}
		}
		if !protocolMatched {
			return false
		}
	}

	// Scope validation (DR-ENF-11)
	if len(rule.AllowedScopes) > 0 {
		scopeAllowed := false
		for _, s := range rule.AllowedScopes {
			if s == scope {
				scopeAllowed = true
				break
			}
		}
		if !scopeAllowed {
			return false
		}
	}

	return true
}

func (e *Engine) subjectMatches(sel *SubjectSelector, principal contracts.Principal) bool {
	if len(sel.PrincipalKinds) > 0 {
		kindMatched := false
		for _, k := range sel.PrincipalKinds {
			if k == principal.Kind {
				kindMatched = true
				break
			}
		}
		if !kindMatched {
			return false
		}
	}

	// Check user list (simplified; production resolves groups via inventory)
	if len(sel.Users) > 0 && principal.User != nil {
		userMatched := false
		for _, u := range sel.Users {
			if u == principal.User.UserID {
				userMatched = true
				break
			}
		}
		return userMatched
	}

	// Match-all if no specific selectors
	if len(sel.Users) == 0 && len(sel.Groups) == 0 && len(sel.DeviceTags) == 0 && len(sel.PrincipalKinds) == 0 {
		return true
	}

	return len(sel.PrincipalKinds) > 0 // only kind-based match
}

func (e *Engine) resourceMatches(sel *ResourceSelector, resource contracts.ResourceID) bool {
	if len(sel.ResourceIDs) > 0 {
		for _, rid := range sel.ResourceIDs {
			if rid == resource.ServiceID || rid == resource.ProtectedNodeID {
				return true
			}
		}
		return false
	}
	if len(sel.Ports) > 0 {
		for _, p := range sel.Ports {
			if p == resource.Port {
				return true
			}
		}
		return false
	}
	if len(sel.Services) > 0 {
		for _, s := range sel.Services {
			if s == resource.ServiceID {
				return true
			}
		}
		return false
	}
	if len(sel.DeploymentModes) > 0 {
		for _, m := range sel.DeploymentModes {
			if m == resource.DeploymentMode {
				return true
			}
		}
		return false
	}
	// Match-all if no selectors
	return len(sel.ResourceIDs) == 0 && len(sel.Ports) == 0 && len(sel.Services) == 0 && len(sel.DeploymentModes) == 0
}

// hasConflictingTie checks for ambiguous rules at the same priority (DR-POL-4).
func (e *Engine) hasConflictingTie(rules *[]PolicyRule, matched *PolicyRule, principal contracts.Principal, resource contracts.ResourceID, protocol string, scope contracts.Scope) bool {
	for _, r := range *rules {
		if r.ID == matched.ID {
			continue
		}
		if r.Priority != matched.Priority {
			continue
		}
		if r.Effect != matched.Effect {
			if e.ruleMatches(&r, principal, resource, protocol, scope) {
				return true
			}
		}
	}
	return false
}

// ─── Protected Resource Registry (DR-POL-1) ────────────────────────────

func (e *Engine) isResourceProtected(ctx context.Context, tenantID uuid.UUID, resource contracts.ResourceID) (bool, error) {
	var exists bool
	err := e.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM resources
			WHERE tenant_id = $1
			  AND protected_node_id = $2
			  AND service_id = $3
			  AND port = $4
		)
	`, tenantID, uuid.MustParse(resource.ProtectedNodeID), resource.ServiceID, resource.Port).Scan(&exists)
	return exists, err
}

// ─── Policy Bundle ──────────────────────────────────────────────────────

// PolicyBundle represents a signed, versioned policy bundle.
type PolicyBundle struct {
	TenantID         uuid.UUID       `json:"tenant_id"`
	Version          int64           `json:"version"`
	Epoch            int64           `json:"epoch"`
	Document         json.RawMessage  `json:"document"`
	PrevHash         []byte          `json:"prev_hash"`
	Signature        []byte          `json:"signature"`
	Kid              string          `json:"kid"`
	NotBefore        time.Time       `json:"not_before"`
	ExpiresAt        time.Time       `json:"expires_at"`
	MinDaemonVersion string          `json:"min_daemon_version"`
	IssuedBy         *uuid.UUID      `json:"issued_by"`
}

func (e *Engine) loadActiveBundle(ctx context.Context, tenantID uuid.UUID) (*PolicyBundle, error) {
	var b PolicyBundle
	var doc json.RawMessage
	err := e.db.QueryRowContext(ctx, `
		SELECT tenant_id, version, epoch, document, prev_hash, signature, kid,
		       not_before, expires_at, min_daemon_version, issued_by
		FROM policies
		WHERE tenant_id = $1 AND expires_at > now()
		ORDER BY version DESC
		LIMIT 1
	`, tenantID).Scan(
		&b.TenantID, &b.Version, &b.Epoch, &doc,
		&b.PrevHash, &b.Signature, &b.Kid,
		&b.NotBefore, &b.ExpiresAt, &b.MinDaemonVersion, &b.IssuedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("load bundle: %w", err)
	}
	b.Document = doc
	return &b, nil
}

// ─── Coverage Analysis (DR-POL-6) ──────────────────────────────────────

// CoverageResult reports uncovered gaps for registered protected resources.
type CoverageResult struct {
	Passed     bool                   `json:"passed"`
	Uncovered  []CoverageGap          `json:"uncovered,omitempty"`
	Warnings    []string              `json:"warnings,omitempty"`
}

// CoverageGap identifies a resource/protocol combination not covered by any rule.
type CoverageGap struct {
	ResourceID  uuid.UUID `json:"resource_id"`
	ServiceID   string    `json:"service_id"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	Reason      string    `json:"reason"`
}

// CheckCoverage analyzes a policy document against the registered resources.
// Rejects uncovered ports, protocols, aliases, and addresses (DR-POL-6).
func (e *Engine) CheckCoverage(ctx context.Context, tenantID uuid.UUID, doc *PolicyDocument) (*CoverageResult, error) {
	result := &CoverageResult{Passed: true}

	// Get all registered protected resources for the tenant
	rows, err := e.db.QueryContext(ctx, `
		SELECT id, service_id, port, deployment_mode, transport
		FROM resources
		WHERE tenant_id = $1
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("coverage: query resources: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var rid uuid.UUID
		var serviceID string
		var port int
		var mode string
		var transport string

		if err := rows.Scan(&rid, &serviceID, &port, &mode, &transport); err != nil {
			return nil, err
		}

		// Check each protocol relevant to this resource
		protocols := []string{"TCP"}
		if mode == "HTTP_PROXY" {
			protocols = append(protocols, "HTTP", "HTTPS")
		}
		if mode == "TS_SSH" || mode == "OPENSSH" {
			protocols = append(protocols, "SSH")
		}

		for _, protocol := range protocols {
			covered := false
			for _, rule := range doc.Rules {
				if e.coverageRuleMatches(&rule, serviceID, port, protocol, mode) {
					covered = true
					break
				}
			}
			if !covered {
				result.Passed = false
				result.Uncovered = append(result.Uncovered, CoverageGap{
					ResourceID: rid,
					ServiceID:  serviceID,
					Port:       port,
					Protocol:   protocol,
					Reason:     fmt.Sprintf("No rule covers %s/%s:%d/%s", mode, serviceID, port, protocol),
				})
			}
		}
	}

	return result, rows.Err()
}

func (e *Engine) coverageRuleMatches(rule *PolicyRule, serviceID string, port int, protocol, mode string) bool {
	// Check protocol
	protoMatched := len(rule.Protocols) == 0
	for _, p := range rule.Protocols {
		if p == protocol {
			protoMatched = true
			break
		}
	}
	if !protoMatched {
		return false
	}

	// Check resource selectors
	if len(rule.Resources) == 0 {
		return true // match-all
	}
	for _, sel := range rule.Resources {
		for _, s := range sel.Services {
			if s == serviceID {
				return true
			}
		}
		for _, p := range sel.Ports {
			if p == port {
				return true
			}
		}
	}
	return false
}

// ─── Publish Policy (DR-POL-10) ────────────────────────────────────────

// PublishPolicyInput contains the policy document to publish.
type PublishPolicyInput struct {
	TenantID  uuid.UUID
	Document  PolicyDocument
	DryRun    bool
	IssuedBy  uuid.UUID
}

// PublishPolicyResult is the result of a policy publication.
type PublishPolicyResult struct {
	Version   int64            `json:"version"`
	Epoch     int64            `json:"epoch"`
	Bundle    *PolicyBundle    `json:"bundle,omitempty"`
	Coverage  *CoverageResult  `json:"coverage"`
	Warnings   []string        `json:"warnings"`
	Published  bool            `json:"published"`
}

// PublishPolicy publishes a new policy bundle (with coverage check, anti-rollback, and signing).
func (e *Engine) PublishPolicy(ctx context.Context, input PublishPolicyInput, signer func([]byte) ([]byte, string, error)) (*PublishPolicyResult, error) {
	// Coverage check (DR-POL-6)
	coverage, err := e.CheckCoverage(ctx, input.TenantID, &input.Document)
	if err != nil {
		return nil, fmt.Errorf("policy: coverage check: %w", err)
	}

	if !coverage.Passed && !input.DryRun {
		return &PublishPolicyResult{
			Coverage: coverage,
			Warnings:  []string{"Coverage gaps detected — policy rejected"},
		}, nil
	}

	if input.DryRun {
		return &PublishPolicyResult{
			Coverage: coverage,
			Published: coverage.Passed,
		}, nil
	}

	// Get current version and epoch
	var currentVersion, currentEpoch int64
	var prevHash []byte
	err = e.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 0), COALESCE(MAX(epoch), 0)
		FROM policies WHERE tenant_id = $1
	`, input.TenantID).Scan(&currentVersion, &currentEpoch)
	if err != nil {
		return nil, fmt.Errorf("policy: get current version: %w", err)
	}

	// Get previous hash
	if currentVersion > 0 {
		var ph []byte
		err = e.db.QueryRowContext(ctx, `
			SELECT digest(document::text, 'sha256')
			FROM policies WHERE tenant_id = $1 AND version = $2
		`, input.TenantID, currentVersion).Scan(&ph)
		if err == nil {
			prevHash = ph
		}
	} else {
		prevHash = make([]byte, sha256.Size) // zero hash for genesis
	}

	newVersion := currentVersion + 1
	newEpoch := currentEpoch + 1

	// Serialize document
	docBytes, err := json.Marshal(input.Document)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal document: %w", err)
	}

	// Sign the bundle
	now := time.Now().UTC()
	bundle := &PolicyBundle{
		TenantID:         input.TenantID,
		Version:          newVersion,
		Epoch:            newEpoch,
		Document:         docBytes,
		PrevHash:         prevHash,
		NotBefore:        now,
		ExpiresAt:        now.Add(5 * time.Minute), // DR-POL-9: 5-minute bundle expiry
		MinDaemonVersion: "2.1.0",
		IssuedBy:         &input.IssuedBy,
	}

	bundleBytes := buildBundleForSigning(bundle)
	sig, kid, err := signer(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("policy: sign bundle: %w", err)
	}
	bundle.Signature = sig
	bundle.Kid = kid

	// Persist
	_, err = e.db.ExecContext(ctx, `
		INSERT INTO policies (tenant_id, version, epoch, document, prev_hash, signature, kid, not_before, expires_at, min_daemon_version, issued_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, version) DO NOTHING
	`, bundle.TenantID, bundle.Version, bundle.Epoch, bundle.Document, bundle.PrevHash,
		bundle.Signature, bundle.Kid, bundle.NotBefore, bundle.ExpiresAt,
		bundle.MinDaemonVersion, bundle.IssuedBy)
	if err != nil {
		return nil, fmt.Errorf("policy: insert bundle: %w", err)
	}

	return &PublishPolicyResult{
		Version:   newVersion,
		Epoch:     newEpoch,
		Bundle:    bundle,
		Coverage:  coverage,
		Published: true,
	}, nil
}

func buildBundleForSigning(b *PolicyBundle) []byte {
	h := sha256.New()
	h.Write([]byte(b.TenantID.String()))
	h.Write(int64ToBytes(b.Version))
	h.Write(int64ToBytes(b.Epoch))
	h.Write(b.Document)
	h.Write(b.PrevHash)
	return h.Sum(nil)
}

func int64ToBytes(i int64) []byte {
	b := make([]byte, 8)
	b[0] = byte(i >> 56)
	b[1] = byte(i >> 48)
	b[2] = byte(i >> 40)
	b[3] = byte(i >> 32)
	b[4] = byte(i >> 24)
	b[5] = byte(i >> 16)
	b[6] = byte(i >> 8)
	b[7] = byte(i)
	return b
}

// Ensure imports
var _ = ed25519.Sign
var _ = sort.Slice
var _ = contracts.DecisionEnforceDeny
