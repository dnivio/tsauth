// Command dnv-daemon is the Dnivio enforcement daemon that runs on protected Tailscale nodes.
// It mediates all access to protected resources per §7 of ENGINEERING.md v2.1.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dnivio/contracts"
	"github.com/dnivio/contracts/cose"
	"github.com/dnivio/daemon/internal/firewall"
	"github.com/dnivio/daemon/internal/grants"
	"github.com/dnivio/daemon/internal/interstitial"
	"github.com/dnivio/daemon/internal/ssh"
	"github.com/dnivio/daemon/internal/tcpproxy"
	"github.com/google/uuid"
)

func main() {
	configPath := flag.String("config", "/etc/dnivio/daemon.json", "path to daemon configuration")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)
	log.Printf("Dnivio Enforcement Daemon starting (ENGINEERING.md v2.1)")

	cfg, err := loadDaemonConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// ─── Initialize Grant Cache ──────────────────────────────────────────
	// Load service trust root for AGT signature verification (C2 fix).
	trustRoot, err := loadTrustRoot(cfg.TrustRootFile)
	if err != nil {
		log.Fatalf("Failed to load trust root: %v", err)
	}
	grantCache, err := grants.NewCache(cfg.GrantCachePath, trustRoot)
	if err != nil {
		log.Fatalf("Failed to initialize grant cache: %v", err)
	}

	// Wire remote consumption callback (C4 fix): single-use grants must
	// be atomically consumed at the Approval Service before local use.
	grantCache.SetRemoteConsume(func(ctx context.Context, jti uuid.UUID) (bool, error) {
		// TODO: Call EnforcementChannel.ConsumeGrant via gRPC
		// Until gRPC is wired, fail closed — single-use grants cannot be consumed
		return false, fmt.Errorf("grants: remote consumption not available — gRPC channel not implemented")
	})

	log.Printf("Grant cache initialized at %s", cfg.GrantCachePath)

	// ─── Initialize Firewall ─────────────────────────────────────────────
	fw := firewall.NewManager()
	if err := fw.ApplyBackendIsolation(cfg.BackendAddr, cfg.BackendPort, cfg.ProxyPort); err != nil {
		log.Fatalf("Failed to apply firewall rules: %v", err)
	}
	defer fw.Stop()
	log.Printf("Firewall rules applied: backend %s:%d isolated behind proxy :%d",
		cfg.BackendAddr, cfg.BackendPort, cfg.ProxyPort)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fw.StartVerification(ctx, cfg.FirewallVerifyInterval)

	// ─── Initialize Interstitial Handler ─────────────────────────────────
	interstitialHandler := interstitial.NewHandler()

	// ─── Initialize SSH Authorizer ────────────────────────────────────────
	sshAuthorizer := ssh.NewAuthorizer(cfg.SSHSocketPath, func(ctx context.Context, req *ssh.ApprovalRequest) (*ssh.ApprovalResult, error) {
		return requestApproval(ctx, req, cfg, grantCache)
	})
	if cfg.SSHEnabled {
		if err := sshAuthorizer.Start(ctx); err != nil {
			log.Printf("WARNING: SSH authorizer failed to start: %v", err)
		} else {
			defer sshAuthorizer.Stop()
			log.Printf("SSH authorizer listening on %s", cfg.SSHSocketPath)
		}
	}

	// ─── Initialize TCP Proxy ────────────────────────────────────────────
	tcpProxy, err := tcpproxy.New(tcpproxy.Config{
		ListenAddr:          fmt.Sprintf(":%d", cfg.ProxyPort),
		BackendAddr:         fmt.Sprintf("%s:%d", cfg.BackendAddr, cfg.BackendPort),
		MaxPendingConns:     cfg.MaxPendingConns,
		MaxPreApprovalBytes: cfg.MaxPreApprovalBytes,
		MaxAggregateMem:     cfg.MaxAggregateMem,
		PreAuthorize: func(ctx context.Context, srcAddr, dstAddr string) (bool, string, error) {
			// TODO: Implement Tailscale ACL evaluation via WhoIs (DR-CAP-2)
			// Until implemented, fail closed.
			return false, "", fmt.Errorf("enforcement: PreAuthorize not implemented — access denied by default (C1)")
		},
		RequestApproval: func(ctx context.Context, connID []byte, srcAddr, dstAddr string) (bool, error) {
			result, err := requestApproval(ctx, &ssh.ApprovalRequest{
				RequestID: uuid.Must(uuid.NewV7()),
				Hostname:  dstAddr,
				Protocol:  "TCP",
				SessionID: connID,
			}, cfg, grantCache)
			if err != nil {
				return false, err
			}
			return result.Approved, nil
		},
	})
	if err != nil {
		log.Fatalf("Failed to create TCP proxy: %v", err)
	}
	defer tcpProxy.Stop()

	if err := tcpProxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start TCP proxy: %v", err)
	}
	log.Printf("TCP proxy listening on :%d -> %s:%d", cfg.ProxyPort, cfg.BackendAddr, cfg.BackendPort)

	// ─── Start HTTPS Server for HTTP_PROXY mode ─────────────────────────
	if cfg.TLSEnabled {
		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			log.Fatalf("Failed to build TLS config: %v", err)
		}

		mux := http.NewServeMux()

		// Dnivio interstitial routes
		mux.HandleFunc("/.dnivio/status/", func(w http.ResponseWriter, r *http.Request) {
			rid, _ := uuid.Parse(r.URL.Path[len("/.dnivio/status/"):])
			interstitialHandler.ServeStatus(w, r, rid)
		})

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Check grant cache for existing session/connection grant
			key := fmt.Sprintf("%s/%s/%s", r.Host, r.Method, r.URL.Path)
			if _, ok := grantCache.Check(key); ok {
				// Grant exists — forward to backend
				forwardToBackend(w, r, cfg.BackendAddr, cfg.BackendPort)
				return
			}

			// No grant — show interstitial
			requestID := contracts.NewRequestID()
			pollCap, redeemCap, err := interstitialHandler.RegisterPending(requestID, 60*time.Second)
			if err != nil {
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}

			interstitial.SetRedeemCookie(w, requestID, redeemCap)
			interstitialHandler.ServeInterstitial(w, r, requestID, pollCap, cfg.BackendAddr)
		})

		httpsServer := &http.Server{
			Addr:      fmt.Sprintf(":%d", cfg.ProxyPort),
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		go func() {
			log.Printf("HTTPS server listening on :%d", cfg.ProxyPort)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server failed: %v", err)
			}
		}()

		defer httpsServer.Shutdown(ctx)
	}

	log.Printf("Dnivio Enforcement Daemon started successfully")
	<-ctx.Done()
	log.Printf("Shutting down...")
}

// ─── Approval Request Helper ──────────────────────────────────────────────

func requestApproval(ctx context.Context, req *ssh.ApprovalRequest, cfg *DaemonConfig, cache *grants.Cache) (*ssh.ApprovalResult, error) {
	// TODO(C1): Implement gRPC EnforcementChannel call to the Approval Service.
	// 1. Dial service at cfg.ServiceEndpoint with mTLS
	// 2. Call EnforcementChannel.RequestApproval(request)
	// 3. Wait for response with timeout (cfg.RequestTimeout)
	// 4. Return result.Approved + result.GrantJTI
	// Until implemented, fail closed — never approve without biometric verification.
	log.Printf("WARNING: Approval requested but enforcement channel not yet implemented — failing closed for %s (%s)", req.Hostname, req.Protocol)
	return &ssh.ApprovalResult{
		Approved:  false,
		SessionID: req.SessionID,
	}, fmt.Errorf("enforcement: gRPC channel not implemented — access denied by default (C1)")
}

func forwardToBackend(w http.ResponseWriter, r *http.Request, backendAddr string, backendPort int) {
	// In production, this proxies the request to the isolated backend
	target := fmt.Sprintf("http://%s:%d", backendAddr, backendPort)
	http.Redirect(w, r, target+r.URL.Path, http.StatusTemporaryRedirect)
}

// ─── Daemon Configuration ─────────────────────────────────────────────────

type DaemonConfig struct {
	GrantCachePath        string        `json:"grant_cache_path"`
	BackendAddr           string        `json:"backend_addr"`
	BackendPort           int           `json:"backend_port"`
	ProxyPort             int           `json:"proxy_port"`
	TLSEnabled            bool          `json:"tls_enabled"`
	TLSCertFile           string        `json:"tls_cert_file"`
	TLSKeyFile            string        `json:"tls_key_file"`
	SSHEnabled            bool          `json:"ssh_enabled"`
	SSHSocketPath         string        `json:"ssh_socket_path"`
	MaxPendingConns       int32         `json:"max_pending_conns"`
	MaxPreApprovalBytes   int32         `json:"max_pre_approval_bytes"`
	MaxAggregateMem       int64         `json:"max_aggregate_mem"`
	FirewallVerifyInterval time.Duration `json:"firewall_verify_interval"`
	ServiceEndpoint       string        `json:"service_endpoint"`
	TrustRootFile         string        `json:"trust_root_file"` // C2: path to grant_sig public key (hex-encoded)
}

func loadDaemonConfig(path string) (*DaemonConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &DaemonConfig{
		GrantCachePath:         "/var/lib/dnivio/grants.db",
		BackendAddr:            "127.0.0.1",
		BackendPort:            8080,
		ProxyPort:              8443,
		TLSEnabled:             true,
		SSHSocketPath:          "/var/run/dnivio/ssh.sock",
		MaxPendingConns:        100,
		MaxPreApprovalBytes:    65536,
		MaxAggregateMem:        268435456,
		FirewallVerifyInterval: 1 * time.Second,
		ServiceEndpoint:        "approval.dnivio.dev:8443",
	}

	// Parse JSON over defaults
	_ = data // Parse in production
	return cfg, nil
}

func buildTLSConfig(cfg *DaemonConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}

	pool := x509.NewCertPool()
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
	}, nil
}

// loadTrustRoot loads the service grant_sig public key for AGT verification (C2).
func loadTrustRoot(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, fmt.Errorf("trust_root_file is required for AGT verification")
	}
	hexBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust root file: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(hexBytes)))
	if err != nil {
		return nil, fmt.Errorf("decode trust root: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid trust root key size %d", len(key))
	}
	return ed25519.PublicKey(key), nil
}

// Ensure imports
var _ = ed25519.Sign
var _ = cose.EncodeCanonical
var _ = net.Listen
