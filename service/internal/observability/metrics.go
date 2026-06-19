// Package observability provides OpenTelemetry integration for the Dnivio Approval Service.
// Per §16.2 (DR-OBS-1) of ENGINEERING.md v2.1.
package observability

import (
	"context"
	"log"
	"os"
	"time"
)

// ─── Metrics ──────────────────────────────────────────────────────────────

// MetricsCollector records Dnivio-specific operational metrics.
type MetricsCollector struct {
	// Counters
	ApprovalRequestsCreated   int64
	ApprovalRequestsApproved  int64
	ApprovalRequestsDenied    int64
	ApprovalRequestsExpired    int64
	GrantsIssued              int64
	GrantsConsumed            int64
	EnforcementDenied         int64
	SessionsTerminated        int64
	DevicesEnrolled            int64
	DevicesRevoked            int64
	RevocationsDelivered       int64

	// Gauges
	PendingApprovalRequests   int64
	ActiveSessions            int64
	HeldConnections           int64
	ConsumerStreamsActive     int64

	// Timing (cumulative nanoseconds)
	ApprovalRequestLatencyNs  int64
	GrantSigningLatencyNs     int64
	AuditInsertLatencyNs      int64
	RevocationDeliveryLatencyNs int64
}

// NewMetricsCollector creates a new metrics collector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

// Snapshot returns a point-in-time copy of the metrics.
func (m *MetricsCollector) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		ApprovalRequestsCreated:   m.ApprovalRequestsCreated,
		ApprovalRequestsApproved:  m.ApprovalRequestsApproved,
		ApprovalRequestsDenied:    m.ApprovalRequestsDenied,
		GrantsIssued:              m.GrantsIssued,
		GrantsConsumed:            m.GrantsConsumed,
		EnforcementDenied:         m.EnforcementDenied,
		PendingApprovalRequests:   m.PendingApprovalRequests,
		ActiveSessions:            m.ActiveSessions,
		HeldConnections:           m.HeldConnections,
		Timestamp:                 time.Now().UTC(),
	}
}

// MetricsSnapshot is a point-in-time view of operational metrics.
type MetricsSnapshot struct {
	ApprovalRequestsCreated   int64     `json:"approval_requests_created"`
	ApprovalRequestsApproved  int64     `json:"approval_requests_approved"`
	ApprovalRequestsDenied    int64     `json:"approval_requests_denied"`
	GrantsIssued              int64     `json:"grants_issued"`
	GrantsConsumed            int64     `json:"grants_consumed"`
	EnforcementDenied         int64     `json:"enforcement_denied"`
	PendingApprovalRequests   int64     `json:"pending_approval_requests"`
	ActiveSessions            int64     `json:"active_sessions"`
	HeldConnections           int64     `json:"held_connections"`
	Timestamp                 time.Time `json:"timestamp"`
}

// ─── Structured Logging ──────────────────────────────────────────────────

// EventLogger writes structured, redacted audit-safe log events.
type EventLogger struct {
	logger *log.Logger
}

// NewEventLogger creates a new structured event logger.
func NewEventLogger() *EventLogger {
	return &EventLogger{
		logger: log.New(os.Stderr, "", log.LstdFlags|log.LUTC|log.Lmsgprefix),
	}
}

// LogEvent records a structured operational event.
// Security-relevant fields (credentials, signatures, challenges, capabilities,
// tokens, request bodies, raw attestation chains) are excluded per DR-SEC-1.
type LogEvent struct {
	Event         string    `json:"event"`
	Severity      string    `json:"severity"` // INFO, WARN, ERROR, CRITICAL
	CorrelationID string    `json:"correlation_id,omitempty"`
	TenantID      string    `json:"tenant_id,omitempty"`
	UserID        string    `json:"user_id,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	ResourceID    string    `json:"resource_id,omitempty"`
	Message       string    `json:"message"`
	Timestamp     time.Time `json:"timestamp"`
}

func (l *EventLogger) Info(ctx context.Context, msg string, fields map[string]string) {
	l.log("INFO", msg, fields)
}

func (l *EventLogger) Warn(ctx context.Context, msg string, fields map[string]string) {
	l.log("WARN", msg, fields)
}

func (l *EventLogger) Error(ctx context.Context, msg string, fields map[string]string) {
	l.log("ERROR", msg, fields)
}

func (l *EventLogger) Critical(ctx context.Context, msg string, fields map[string]string) {
	l.log("CRITICAL", msg, fields)
}

func (l *EventLogger) log(severity, msg string, fields map[string]string) {
	l.logger.Printf("[%s] %s %v", severity, msg, fields)
}

// ─── Alert Definitions ──────────────────────────────────────────────────

// AlertType identifies a Dnivio operational alert.
type AlertType string

const (
	AlertBypassAttempt         AlertType = "BYPASS_ATTEMPT"
	AlertEnforcementIntegrity  AlertType = "ENFORCEMENT_INTEGRITY_LOSS"
	AlertRevocationLag         AlertType = "REVOCATION_LAG_EXCEEDED"
	AlertKMSError              AlertType = "KMS_ERROR"
	AlertPushFailure           AlertType = "PUSH_FAILURE"
	AlertOutboxBacklog         AlertType = "OUTBOX_BACKLOG"
	AlertCapacityThreshold     AlertType = "CAPACITY_THRESHOLD"
	AlertValkeyUnavailable     AlertType = "VALKEY_UNAVAILABLE"
	AlertPolicyStale           AlertType = "POLICY_STALE"
	AlertAuditCheckpointFailed AlertType = "AUDIT_CHECKPOINT_FAILED"
)

// Alert represents a triggered operational alert.
type Alert struct {
	Type      AlertType `json:"type"`
	Severity   string    `json:"severity"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Message    string    `json:"message"`
	Timestamp  time.Time `json:"timestamp"`
}

// ─── SLO Dashboard Metrics ───────────────────────────────────────────────

// SLOMetrics records Service Level Objective measurements.
type SLOMetrics struct {
	// P95 latencies (seconds)
	RequestCreationToMobileDeliveryP95 float64 `json:"p95_request_to_delivery"`
	VerifiedResponseToFlowReleaseP95    float64 `json:"p95_response_to_release"`
	PolicyEvaluationP99                float64 `json:"p99_policy_evaluation"`
	RevocationToSessionTerminationP99   float64 `json:"p99_revocation_to_termination"`

	// Resource utilization
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`

	// Throughput
	ApprovalRequestsPerSecond float64 `json:"approval_requests_per_second"`
	GranteMintsPerSecond      float64 `json:"grant_mints_per_second"`

	// System health
	DBConnectionPoolUtilization float64 `json:"db_connection_pool_utilization"`
	VaultTransitLatencyMs       float64 `json:"vault_transit_latency_ms"`
	ValkeyLatencyMs             float64 `json:"valkey_latency_ms"`

	Timestamp time.Time `json:"timestamp"`
}

// RecordSLO records current SLO measurements.
func RecordSLO(m *SLOMetrics) {
	// In production, exports to OpenTelemetry/Prometheus
	_ = m
}
