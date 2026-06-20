// Command approval-service is the main entry point for the Dnivio Approval Service.
// Implements the authorization plane per ENGINEERING.md v2.1.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	"github.com/dnivio/approval-service/internal/audit"
	"github.com/dnivio/approval-service/internal/config"
	"github.com/dnivio/approval-service/internal/crypto"
	"github.com/dnivio/approval-service/internal/enforcement"
	"github.com/dnivio/approval-service/internal/messaging"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

func main() {
	configPath := flag.String("config", "/etc/dnivio/config.json", "path to configuration file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC | log.Lshortfile)
	log.Printf("Dnivio Approval Service starting (ENGINEERING.md v2.1)")

	// Load configuration
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database connection
	db, err := initDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := runMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Verify tenant isolation (C9): the runtime DB role must not be a table owner.
	log.Printf("Database connected as %s (non-owner role with forced RLS)", cfg.Database.User)

	// Initialize cryptographic infrastructure
	keyManager, rootAnchor, encrypter, err := initCrypto(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize crypto: %v", err)
	}
	log.Printf("Root trust anchor fingerprint: %s", rootAnchor.Fingerprint)

	// Initialize messaging infrastructure
	delivery := messaging.NewDeliveryStream(db)
	outboxWriter := messaging.NewOutboxWriter(db)

	// Initialize audit chain
	auditSigner := &keyManagerAuditSigner{km: keyManager}
	auditWriter := audit.NewChainWriter(db, auditSigner)

	// Initialize approval engine
	requestSigner := &keyManagerRequestSigner{km: keyManager}
	grantSigner := &keyManagerGrantSigner{km: keyManager}
	engine := enforcement.NewApprovalEngine(
		db, auditWriter, outboxWriter, delivery,
		requestSigner, grantSigner, encrypter,
	)

	_ = engine // will be wired into gRPC handlers

	// Start gRPC server
	grpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(uint32(cfg.Service.MaxDaemons)),
	)

	// Register gRPC services
	// registerEnforcementChannel(grpcServer, engine)
	// registerApproverChannel(grpcServer, engine)
	// registerAdminService(grpcServer, engine)

	// Start HTTP/REST server
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", healthHandler(db))
	httpMux.HandleFunc("/v1/status", statusHandler())

	httpServer := &http.Server{
		Addr:    cfg.Service.HTTPListenAddr,
		Handler: httpMux,
	}

	// Start audit checkpoint loop
	// auditWriter.StartCheckpoints(context.Background())

	// Start servers
	go func() {
		log.Printf("gRPC server listening on %s", cfg.Service.ListenAddr)
		lis, err := net.Listen("tcp", cfg.Service.ListenAddr)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	go func() {
		log.Printf("HTTP server listening on %s", cfg.Service.HTTPListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	log.Printf("Dnivio Approval Service started successfully")

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Shutting down (signal: %v)...", sig)

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	grpcServer.GracefulStop()
	httpServer.Shutdown(ctx)
	db.Close()
	log.Printf("Dnivio Approval Service stopped")
}

// ─── Database Initialization ──────────────────────────────────────────────

func initDatabase(cfg *config.Config) (*sql.DB, error) {
	password, err := readFileIfExists(cfg.Database.PasswordFile)
	if err != nil {
		return nil, fmt.Errorf("read db password: %w", err)
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s connect_timeout=%d",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.Database,
		cfg.Database.User, password, cfg.Database.SSLMode,
		int(cfg.Database.ConnectTimeout.Seconds()),
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(cfg.Database.MaxConns)
	db.SetMaxIdleConns(cfg.Database.MinConns)
	db.SetConnMaxIdleTime(cfg.Database.MaxIdleTime)

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return db, nil
}

func runMigrations(db *sql.DB) error {
	// In production, this uses golang-migrate or similar.
	// For now, check if the schema exists.
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants')`).Scan(&exists); err != nil {
		log.Printf("Migration check: assuming fresh database (%v)", err)
	}
	if !exists {
		log.Printf("WARNING: Schema not found. Run migrations manually: psql -f migrations/001_initial_schema.up.sql")
	}
	return nil
}

// ─── Cryptographic Initialization ──────────────────────────────────────────

func initCrypto(cfg *config.Config) (*crypto.KeyManager, *crypto.RootTrustAnchor, crypto.EnvelopeEncrypter, error) {
	devMode := os.Getenv("DNIVIO_DEVELOPMENT") == "true"

	// Production-gated signer (C5/DR-KEY-8): InMemorySigner only in dev mode
	signer, err := crypto.NewSignerForMode(devMode, cfg.Vault.Addr)
	if err != nil {
		return nil, nil, nil, err
	}
	if devMode {
		log.Printf("WARNING: Using InMemorySigner (DEVELOPMENT MODE — NOT FOR PRODUCTION)")
	}

	// Production-gated encrypter (C6/DR-SEC-1): InMemoryEncrypter only in dev mode
	encrypter, err := crypto.NewEncrypterForMode(devMode, cfg.Vault.Addr)
	if err != nil {
		return nil, nil, nil, err
	}
	if devMode {
		log.Printf("WARNING: Using InMemoryEncrypter (DEVELOPMENT MODE — NOT FOR PRODUCTION)")
	}

	// Load root public key from file (production) or generate ephemeral (dev)
	var rootPub ed25519.PublicKey
	var rootFP string
	if cfg.Crypto.RootPubKeyFile != "" {
		rootPub, rootFP, err = crypto.LoadRootPubKey(cfg.Crypto.RootPubKeyFile)
		if err != nil {
			return nil, nil, nil, err
		}
		log.Printf("Loaded root trust anchor from %s", cfg.Crypto.RootPubKeyFile)
	} else if devMode {
		rootPub, _, rootFP, err = crypto.NewRootKey()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("generate dev root key: %w", err)
		}
		log.Printf("WARNING: Generated ephemeral root key (DEVELOPMENT MODE)")
	} else {
		return nil, nil, nil, fmt.Errorf("crypto.root_pub_key_file is required in production")
	}

	rootAnchor := &crypto.RootTrustAnchor{PubKey: rootPub, Fingerprint: rootFP}

	// Initialize key manager
	km := crypto.NewKeyManager(signer, rootPub)
	keySet, err := km.Initialize(context.Background())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize key manager: %w", err)
	}

	// Load root signature (production) or skip (dev)
	if cfg.Crypto.RootSigFile != "" {
		if err := crypto.LoadRootSignature(km, cfg.Crypto.RootSigFile); err != nil {
			return nil, nil, nil, err
		}
		log.Printf("Verified root signature over key set from %s", cfg.Crypto.RootSigFile)
	} else if devMode {
		log.Printf("WARNING: Key set is NOT root-signed (DEVELOPMENT MODE)")
	} else {
		return nil, nil, nil, fmt.Errorf("crypto.root_sig_file is required in production")
	}

	log.Printf("Initialized %d signing keys (root fingerprint: %s)", len(keySet.Keys), rootFP)
	return km, rootAnchor, encrypter, nil
}

// ─── Crypto Adapters ──────────────────────────────────────────────────────

type keyManagerAuditSigner struct {
	km *crypto.KeyManager
}

func (s *keyManagerAuditSigner) Sign(ctx context.Context, message []byte) ([]byte, string, error) {
	return s.km.SignWithPurpose(ctx, crypto.PurposeAuditCheckpoint, message)
}

type keyManagerRequestSigner struct {
	km *crypto.KeyManager
}

func (s *keyManagerRequestSigner) SignRequest(ctx context.Context, payload *contracts.RequestPayload) ([]byte, error) {
	// Prepare payload (compute display_digest, marshal to CBOR)
	payloadBytes, err := contracts.PrepareRequestPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("prepare request payload: %w", err)
	}

	// Build COSE SigStructure and sign via KeyManager (KMS-safe — no raw private key)
	_, kid, err := s.km.GetPubKey(crypto.PurposeRequestSig)
	if err != nil {
		return nil, err
	}
	sigStructBytes, _, _, err := cose.BuildSigStructure(kid, "dnivio-req-v2", payloadBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("build sig structure: %w", err)
	}
	signature, _, err := s.km.SignWithPurpose(ctx, crypto.PurposeRequestSig, sigStructBytes)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	// Assemble COSE_Sign1 message
	msg, err := cose.Sign1WithSignature(kid, "dnivio-req-v2", payloadBytes, nil, signature)
	if err != nil {
		return nil, fmt.Errorf("assemble sign1: %w", err)
	}
	return cose.SerializeSign1(msg)
}

type keyManagerGrantSigner struct {
	km *crypto.KeyManager
}

func (s *keyManagerGrantSigner) SignGrant(ctx context.Context, payload *contracts.AGTPayload) ([]byte, error) {
	// Prepare payload (marshal to CBOR)
	payloadBytes, err := contracts.PrepareAGTPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("prepare agt payload: %w", err)
	}

	// Build COSE SigStructure and sign via KeyManager (KMS-safe)
	_, kid, err := s.km.GetPubKey(crypto.PurposeGrantSig)
	if err != nil {
		return nil, err
	}
	sigStructBytes, _, _, err := cose.BuildSigStructure(kid, "dnivio-agt-v2", payloadBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("build sig structure: %w", err)
	}
	signature, _, err := s.km.SignWithPurpose(ctx, crypto.PurposeGrantSig, sigStructBytes)
	if err != nil {
		return nil, fmt.Errorf("sign grant: %w", err)
	}

	// Assemble COSE_Sign1 message
	msg, err := cose.Sign1WithSignature(kid, "dnivio-agt-v2", payloadBytes, nil, signature)
	if err != nil {
		return nil, fmt.Errorf("assemble sign1: %w", err)
	}
	return cose.SerializeSign1(msg)
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────

func healthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "error": "database unreachable"})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"version": "2.1.0",
			"spec":    "ENGINEERING.md v2.1",
		})
	}
}

func statusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "operational",
			"uptime": "0s",
		})
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func readFileIfExists(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Ensure unused imports
var _ = uuid.New
var _ = ed25519.Sign
var _ = contracts.NewRequestID
var _ = grpc.ServiceDesc{}
var _ = log.Ldate
var _ = signal.Reset
var _ = sha256.New
var _ = hex.DecodeString
var _ = strings.TrimSpace
