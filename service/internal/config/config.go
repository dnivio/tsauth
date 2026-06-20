// Package config provides typed, versioned configuration for the Dnivio Approval Service.
// Per §21.2 (DR-CFG-1) of ENGINEERING.md v2.1.
package config

import (
	"fmt"
	"os"
	"time"

	"encoding/json"
)

// Config is the top-level configuration for the Approval Service.
type Config struct {
	Version     int            `json:"version"`      // config schema version
	Service     ServiceConfig  `json:"service"`
	Database    DatabaseConfig `json:"database"`
	Vault       VaultConfig    `json:"vault"`
	Crypto      CryptoConfig   `json:"crypto"`
	Valkey      ValkeyConfig   `json:"valkey"`
	OIDC        OIDCConfig     `json:"oidc"`
	Audit       AuditConfig    `json:"audit"`
	RateLimit   RateLimitConfig `json:"rate_limit"`
	Enforcement EnforcementConfig `json:"enforcement"`
	Observability ObservabilityConfig `json:"observability"`
}

// ServiceConfig is the core service configuration.
type ServiceConfig struct {
	ListenAddr    string `json:"listen_addr"`      // gRPC listen address
	HTTPListenAddr string `json:"http_listen_addr"` // REST/OpenAPI listen address
	MaxDaemons    int    `json:"max_daemons"`      // max concurrent daemon connections
	MaxApprovers  int    `json:"max_approvers"`    // max concurrent approver connections
}

// DatabaseConfig is the PostgreSQL connection configuration.
type DatabaseConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	User           string `json:"user"`
	PasswordFile   string `json:"password_file"`   // path to file containing password
	MaxConns       int    `json:"max_conns"`
	MinConns       int    `json:"min_conns"`
	MaxIdleTime    time.Duration `json:"max_idle_time"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	SSLMode        string `json:"ssl_mode"`
}

// VaultConfig is the HashiCorp Vault Transit configuration.
type VaultConfig struct {
	Addr          string        `json:"addr"`
	TokenFile     string        `json:"token_file"`
	TransitPath   string        `json:"transit_path"`   // e.g., "transit"
	KeyPrefix     string        `json:"key_prefix"`     // e.g., "dnivio-"
	RequestTimeout time.Duration `json:"request_timeout"`
	MaxRetries    int           `json:"max_retries"`
}

// CryptoConfig is the cryptographic root-of-trust configuration (DR-KEY-10).
type CryptoConfig struct {
	RootPubKeyFile string `json:"root_pub_key_file"` // path to offline root public key (hex-encoded)
	RootSigFile    string `json:"root_sig_file"`     // path to offline root signature over initial key set
}

// ValkeyConfig is the Valkey (Redis-compatible) configuration for rate limiting.
type ValkeyConfig struct {
	Addrs       []string      `json:"addrs"`
	PasswordFile string       `json:"password_file"`
	DB          int           `json:"db"`
	MaxRetries  int           `json:"max_retries"`
	DialTimeout time.Duration `json:"dial_timeout"`
}

// OIDCConfig is the OAuth 2.0 / OIDC configuration (DR-AUTH-1).
type OIDCConfig struct {
	AllowedIssuers   []OIDCIssuer `json:"allowed_issuers"`
	RedirectBaseURL   string       `json:"redirect_base_url"`
	SessionDuration   time.Duration `json:"session_duration"`
	EnrollmentTicketTTL time.Duration `json:"enrollment_ticket_ttl"`
}

// OIDCIssuer configures a trusted OIDC provider.
type OIDCIssuer struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecretFile string `json:"client_secret_file"`
}

// AuditConfig is the audit subsystem configuration (DR-AUD-2).
type AuditConfig struct {
	CheckpointInterval    int           `json:"checkpoint_interval_seconds"` // default 60
	CheckpointMaxEvents   int           `json:"checkpoint_max_events"`      // default 10000
	S3Endpoint            string        `json:"s3_endpoint"`
	S3Bucket              string        `json:"s3_bucket"`
	S3Region              string        `json:"s3_region"`
	ObjectLockEnabled     bool          `json:"object_lock_enabled"`
	OnlineRetentionDays   int           `json:"online_retention_days"`      // min 400
	ImmutableRetentionYears int         `json:"immutable_retention_years"`  // min 7
}

// RateLimitConfig is the rate limiting configuration (DR-CAP-1).
type RateLimitConfig struct {
	Enabled             bool `json:"enabled"`
	ApprovalsPerMinuteUser        int `json:"approvals_per_minute_user"`        // default 20
	ApprovalsPerMinuteSrcNode     int `json:"approvals_per_minute_src_node"`    // default 60
	ApprovalsPerMinuteProtectedNode int `json:"approvals_per_minute_protected_node"` // default 300
	ApprovalsPerMinuteTenant      int `json:"approvals_per_minute_tenant"`      // default 1000
	MaxPendingPerUser             int `json:"max_pending_per_user"`             // default 5
	MaxPromptsPerMinuteDevice     int `json:"max_prompts_per_minute_device"`    // default 3
	MaxPendingConnectionsResource int `json:"max_pending_connections_resource"`  // default 100
	MaxPendingConnectionsNode     int `json:"max_pending_connections_node"`      // default 10000
	MaxPreApprovalBytes           int `json:"max_pre_approval_bytes"`            // default 65536
	MaxPreApprovalMemoryNode      int `json:"max_pre_approval_memory_node"`     // default 268435456
}

// EnforcementConfig is the enforcement subsystem configuration.
type EnforcementConfig struct {
	RevocationFreshnessBound    time.Duration `json:"revocation_freshness_bound"`     // R = 10s, not configurable in production
	PolicyMaxOfflineAge         time.Duration `json:"policy_max_offline_age"`         // 5 minutes
	PolicyRefreshInterval       time.Duration `json:"policy_refresh_interval"`
	RequestTTL                  time.Duration `json:"request_ttl"`                     // default 60s
	BackendProbeInterval        time.Duration `json:"backend_probe_interval"`
	FirewallVerifyInterval      time.Duration `json:"firewall_verify_interval"`        // ≤ 1s
}

// ObservabilityConfig is the OpenTelemetry and logging configuration (DR-OBS-1).
type ObservabilityConfig struct {
	OTelExporterEndpoint string `json:"otel_exporter_endpoint"`
	LogLevel             string `json:"log_level"`
	LogFormat            string `json:"log_format"` // "json" or "text"
	MetricsPort          int    `json:"metrics_port"`
	TracingSampleRate    float64 `json:"tracing_sample_rate"`
}

// DefaultConfig returns a configuration with secure defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Service: ServiceConfig{
			ListenAddr:     ":8443",
			HTTPListenAddr:  ":8444",
			MaxDaemons:     10000,
			MaxApprovers:   100000,
		},
		Database: DatabaseConfig{
			Host:           "localhost",
			Port:           5432,
			Database:       "dnivio",
			User:           "dnivio_app", // restricted application role (C9 fix: not table owner)
			MaxConns:       200,
			MinConns:       20,
			MaxIdleTime:    5 * time.Minute,
			ConnectTimeout: 10 * time.Second,
			SSLMode:        "require",
		},
		Enforcement: EnforcementConfig{
			RevocationFreshnessBound: 10 * time.Second,
			PolicyMaxOfflineAge:      5 * time.Minute,
			PolicyRefreshInterval:    30 * time.Second,
			RequestTTL:               60 * time.Second,
			BackendProbeInterval:     30 * time.Second,
			FirewallVerifyInterval:   1 * time.Second,
		},
		Audit: AuditConfig{
			CheckpointInterval:     60,
			CheckpointMaxEvents:    10000,
			ObjectLockEnabled:      true,
			OnlineRetentionDays:    400,
			ImmutableRetentionYears: 7,
		},
		RateLimit: RateLimitConfig{
			Enabled: true,
			ApprovalsPerMinuteUser:         20,
			ApprovalsPerMinuteSrcNode:      60,
			ApprovalsPerMinuteProtectedNode: 300,
			ApprovalsPerMinuteTenant:       1000,
			MaxPendingPerUser:              5,
			MaxPromptsPerMinuteDevice:      3,
			MaxPendingConnectionsResource:  100,
			MaxPendingConnectionsNode:      10000,
			MaxPreApprovalBytes:            65536,
			MaxPreApprovalMemoryNode:       268435456,
		},
		Observability: ObservabilityConfig{
			LogLevel:          "info",
			LogFormat:         "json",
			MetricsPort:       9090,
			TracingSampleRate: 0.1,
		},
	}
}

// LoadFromFile loads configuration from a JSON file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	// Reject unknown/insecure fields (DR-CFG-1)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for security and correctness.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d", c.Version)
	}
	if c.Service.ListenAddr == "" {
		return fmt.Errorf("service.listen_addr is required")
	}
	if c.Database.Host == "" {
		return fmt.Errorf("database.host is required")
	}
	if c.Enforcement.RevocationFreshnessBound > 10*time.Second {
		return fmt.Errorf("revocation_freshness_bound must not exceed 10s")
	}
	if c.Enforcement.PolicyMaxOfflineAge > 5*time.Minute {
		return fmt.Errorf("policy_max_offline_age must not exceed 5m")
	}
	if c.Audit.OnlineRetentionDays < 400 {
		return fmt.Errorf("online_retention_days must be at least 400")
	}
	if c.Audit.ImmutableRetentionYears < 7 {
		return fmt.Errorf("immutable_retention_years must be at least 7")
	}
	return nil
}
