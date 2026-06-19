// Package ratelimit implements Valkey-backed hierarchical token buckets for Dnivio.
// Per §20.1 (DR-CAP-1) of ENGINEERING.md v2.1.
// Uses atomic Lua scripts for token-bucket operations. If Valkey is unavailable, fails closed.
package ratelimit

import (
	"context"
	"fmt"
	"time"
)

// ─── Bucket Interface ────────────────────────────────────────────────────

// BucketStore abstracts the token bucket storage backend (Valkey in production).
type BucketStore interface {
	// Allow attempts to consume one token from the named bucket.
	// Returns (allowed, remaining, reset_at, error).
	Allow(ctx context.Context, key string, rate int, burst int, period time.Duration) (bool, int, time.Time, error)

	// Ping checks if the store is reachable.
	Ping(ctx context.Context) error
}

// ─── Hierarchical Rate Limiter ───────────────────────────────────────────

// Limiter enforces hierarchical rate limits across global, tenant, user,
// source-node, protected-node, resource, device, and source-IP levels.
type Limiter struct {
	store  BucketStore
	config Config
}

// Config defines the rate limit configuration.
type Config struct {
	Enabled                        bool `json:"enabled"`
	ApprovalsPerMinuteUser         int  `json:"approvals_per_minute_user"`
	ApprovalsPerMinuteSrcNode      int  `json:"approvals_per_minute_src_node"`
	ApprovalsPerMinuteProtectedNode int `json:"approvals_per_minute_protected_node"`
	ApprovalsPerMinuteTenant       int  `json:"approvals_per_minute_tenant"`
	ApprovalsPerMinuteGlobal       int  `json:"approvals_per_minute_global"`
	MaxPendingPerUser              int  `json:"max_pending_per_user"`
	MaxPromptsPerMinuteDevice      int  `json:"max_prompts_per_minute_device"`
	MaxPendingConnectionsResource  int  `json:"max_pending_connections_resource"`
	MaxPendingConnectionsNode      int  `json:"max_pending_connections_node"`
	MaxPreApprovalBytes             int  `json:"max_pre_approval_bytes"`
	MaxPreApprovalMemoryNode       int  `json:"max_pre_approval_memory_node"`
	TenantFairSharePercent         int  `json:"tenant_fair_share_percent"`
}

// DefaultConfig returns the baseline hard ceilings per DR-CAP-1.
func DefaultConfig() Config {
	return Config{
		Enabled:                         true,
		ApprovalsPerMinuteUser:          20,
		ApprovalsPerMinuteSrcNode:       60,
		ApprovalsPerMinuteProtectedNode: 300,
		ApprovalsPerMinuteTenant:        1000,
		ApprovalsPerMinuteGlobal:        10000,
		MaxPendingPerUser:               5,
		MaxPromptsPerMinuteDevice:       3,
		MaxPendingConnectionsResource:   100,
		MaxPendingConnectionsNode:       10000,
		MaxPreApprovalBytes:             65536,     // 64 KiB
		MaxPreApprovalMemoryNode:        268435456, // 256 MiB
		TenantFairSharePercent:          25,
	}
}

// NewLimiter creates a new rate limiter.
func NewLimiter(store BucketStore, cfg Config) *Limiter {
	return &Limiter{store: store, config: cfg}
}

// ─── Approval Rate Limits ────────────────────────────────────────────────

// CheckApprovalRate checks all approval rate limits for a request.
// Returns an error if any limit is exceeded; nil if the request can proceed.
func (l *Limiter) CheckApprovalRate(ctx context.Context, tenantID, userID, srcNodeID, protectedNodeID, deviceID, sourceIP string) error {
	if !l.config.Enabled {
		return nil
	}

	// Check store availability (fail closed, DR-CAP-1)
	if err := l.store.Ping(ctx); err != nil {
		return fmt.Errorf("ratelimit: valkey unavailable — failing closed: %w", err)
	}

	checks := []struct {
		name string
		key  string
		rate int
	}{
		{"global", "ratelimit:approval:global", l.config.ApprovalsPerMinuteGlobal},
		{"tenant", fmt.Sprintf("ratelimit:approval:tenant:%s", tenantID), l.config.ApprovalsPerMinuteTenant},
		{"user", fmt.Sprintf("ratelimit:approval:user:%s:%s", tenantID, userID), l.config.ApprovalsPerMinuteUser},
		{"src_node", fmt.Sprintf("ratelimit:approval:src_node:%s:%s", tenantID, srcNodeID), l.config.ApprovalsPerMinuteSrcNode},
		{"protected_node", fmt.Sprintf("ratelimit:approval:node:%s:%s", tenantID, protectedNodeID), l.config.ApprovalsPerMinuteProtectedNode},
		{"device_prompt", fmt.Sprintf("ratelimit:prompt:device:%s:%s", tenantID, deviceID), l.config.MaxPromptsPerMinuteDevice},
	}

	for _, check := range checks {
		allowed, remaining, _, err := l.store.Allow(ctx, check.key, check.rate, check.rate, time.Minute)
		if err != nil {
			return fmt.Errorf("ratelimit: %s check failed: %w", check.name, err)
		}
		if !allowed {
			return fmt.Errorf("ratelimit: %s limit exceeded (remaining=%d)", check.name, remaining)
		}
	}

	return nil
}

// ─── Pending Request Limits ──────────────────────────────────────────────

// CheckPendingLimit checks if the user has too many pending approval requests.
func (l *Limiter) CheckPendingLimit(ctx context.Context, tenantID, userID string, currentPending int) error {
	if !l.config.Enabled {
		return nil
	}
	if currentPending >= l.config.MaxPendingPerUser {
		return fmt.Errorf("ratelimit: max pending requests per user (%d) exceeded", l.config.MaxPendingPerUser)
	}
	return nil
}

// ─── Connection Limits (DR-CAP-2) ────────────────────────────────────────

// CheckHeldConnectionLimit checks pending TCP connection limits.
func (l *Limiter) CheckHeldConnectionLimit(ctx context.Context, tenantID, srcNodeID, resourceID string, currentPendingPerResource, currentPendingPerNode int) error {
	if !l.config.Enabled {
		return nil
	}
	if currentPendingPerResource >= l.config.MaxPendingConnectionsResource {
		return fmt.Errorf("ratelimit: max pending connections per resource (%d) exceeded", l.config.MaxPendingConnectionsResource)
	}
	if currentPendingPerNode >= l.config.MaxPendingConnectionsNode {
		return fmt.Errorf("ratelimit: max pending connections per node (%d) exceeded", l.config.MaxPendingConnectionsNode)
	}
	return nil
}

// ─── In-Memory Bucket Store (for development/testing) ─────────────────────

// InMemoryStore implements BucketStore with in-memory token buckets.
// NOT for production — production uses Valkey with Lua atomic operations.
type InMemoryStore struct {
	buckets map[string]*tokenBucket
}

// NewInMemoryStore creates a new in-memory bucket store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		buckets: make(map[string]*tokenBucket),
	}
}

type tokenBucket struct {
	tokens   int
	lastRefill time.Time
}

func (s *InMemoryStore) Allow(ctx context.Context, key string, rate int, burst int, period time.Duration) (bool, int, time.Time, error) {
	now := time.Now()

	bucket, ok := s.buckets[key]
	if !ok {
		bucket = &tokenBucket{tokens: burst, lastRefill: now}
		s.buckets[key] = bucket
	}

	// Refill tokens
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := int(float64(elapsed) / float64(period) * float64(rate))
	if tokensToAdd > 0 {
		bucket.tokens += tokensToAdd
		if bucket.tokens > burst {
			bucket.tokens = burst
		}
		bucket.lastRefill = now
	}

	// Consume token
	if bucket.tokens > 0 {
		bucket.tokens--
		return true, bucket.tokens, now.Add(period), nil
	}

	return false, 0, now.Add(period), nil
}

func (s *InMemoryStore) Ping(ctx context.Context) error {
	return nil
}

// ─── No-Op Bucket Store (rate limiting disabled) ─────────────────────────

// NoOpStore always allows operations (rate limiting disabled).
type NoOpStore struct{}

func (s *NoOpStore) Allow(ctx context.Context, key string, rate int, burst int, period time.Duration) (bool, int, time.Time, error) {
	return true, rate, time.Now().Add(period), nil
}

func (s *NoOpStore) Ping(ctx context.Context) error {
	return nil
}
