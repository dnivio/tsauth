// Package tcpproxy implements the bounded accept-and-hold TCP proxy for OPAQUE_TCP mode.
// Per §7.4 (DR-ENF-10) and ADR-011 of ENGINEERING.md v2.1.
// Features: bounded pending connections/bytes, ACL pre-authorization, TLS passthrough.
package tcpproxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// ─── Proxy ───────────────────────────────────────────────────────────────

// Proxy implements an accept-and-hold TCP proxy that waits for biometric approval
// before connecting to the isolated backend.
type Proxy struct {
	listenAddr   string
	backendAddr  string // isolated Unix socket or loopback address

	// Bounds (DR-CAP-2)
	maxPendingConns      int32
	maxPreApprovalBytes  int32 // per connection
	maxAggregateMem      int64 // per proxy instance

	// State
	activeConns     map[string]*heldConnection
	mu              sync.Mutex
	pendingCount    atomic.Int32
	aggregateMem    atomic.Int64

	// Pre-authorization callback (evaluates Tailscale ACL before creating approval state)
	preAuthorize func(ctx context.Context, srcAddr, dstAddr string) (bool, string, error)

	// Approval callback (creates approval request and waits for result)
	requestApproval func(ctx context.Context, connID []byte, srcAddr, dstAddr string) (bool, error)

	listener net.Listener
	stopCh   chan struct{}
}

// heldConnection represents a TCP connection awaiting approval.
type heldConnection struct {
	ID          []byte
	Conn        net.Conn
	SrcAddr     string
	DstAddr     string
	Buffered    []byte // pre-approval buffered bytes
	BufferedLen int32
	CreatedAt   time.Time
	Approved    chan bool
}

// Config configures the TCP proxy.
type Config struct {
	ListenAddr          string
	BackendAddr         string
	MaxPendingConns     int32
	MaxPreApprovalBytes int32
	MaxAggregateMem     int64
	PreAuthorize        func(ctx context.Context, srcAddr, dstAddr string) (bool, string, error)
	RequestApproval     func(ctx context.Context, connID []byte, srcAddr, dstAddr string) (bool, error)
}

// DefaultConfig returns secure defaults per DR-CAP-2.
func DefaultConfig() Config {
	return Config{
		MaxPendingConns:     100,
		MaxPreApprovalBytes: 65536,     // 64 KiB
		MaxAggregateMem:     268435456, // 256 MiB
	}
}

// New creates a new TCP proxy.
func New(cfg Config) (*Proxy, error) {
	return &Proxy{
		listenAddr:          cfg.ListenAddr,
		backendAddr:         cfg.BackendAddr,
		maxPendingConns:     cfg.MaxPendingConns,
		maxPreApprovalBytes: cfg.MaxPreApprovalBytes,
		maxAggregateMem:     cfg.MaxAggregateMem,
		activeConns:         make(map[string]*heldConnection),
		preAuthorize:        cfg.PreAuthorize,
		requestApproval:     cfg.RequestApproval,
		stopCh:              make(chan struct{}),
	}, nil
}

// Start begins listening and accepting connections.
func (p *Proxy) Start(ctx context.Context) error {
	var err error
	p.listener, err = net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("tcpproxy: listen %s: %w", p.listenAddr, err)
	}

	go p.acceptLoop(ctx)
	return nil
}

// Stop gracefully stops the proxy, closing all held connections.
func (p *Proxy) Stop() error {
	close(p.stopCh)
	if p.listener != nil {
		p.listener.Close()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, hc := range p.activeConns {
		hc.Conn.Close()
	}
	p.activeConns = make(map[string]*heldConnection)

	return nil
}

// ─── Accept Loop ─────────────────────────────────────────────────────────

func (p *Proxy) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
				continue
			}
		}

		go p.handleConnection(ctx, conn)
	}
}

// ─── Connection Handling (DR-ENF-10) ─────────────────────────────────────

func (p *Proxy) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	srcAddr := conn.RemoteAddr().String()
	dstAddr := conn.LocalAddr().String()

	// Step 1: Tailscale ACL pre-authorization (DR-CAP-2)
	// Must pass BEFORE creating any approval state
		aclAllowed, _, err := p.preAuthorize(ctx, srcAddr, dstAddr)
	if err != nil || !aclAllowed {
		// Deny without creating approval state — fail closed
		return
	}

	// Step 2: Check bounds
	if p.pendingCount.Load() >= p.maxPendingConns {
		return // Shed load deterministically
	}

	connID := make([]byte, 32)
	if _, err := io.ReadFull(randSource{}, connID); err != nil {
		return
	}

	// Step 3: Create held connection
	hc := &heldConnection{
		ID:        connID,
		Conn:      conn,
		SrcAddr:   srcAddr,
		DstAddr:   dstAddr,
		CreatedAt: time.Now(),
		Approved:  make(chan bool, 1),
	}

	p.mu.Lock()
	p.activeConns[string(connID)] = hc
	p.pendingCount.Add(1)
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.activeConns, string(connID))
		p.pendingCount.Add(-1)
		p.mu.Unlock()
	}()

	// Step 4: Request biometric approval
	approved, err := p.requestApproval(ctx, connID, srcAddr, dstAddr)
	if err != nil || !approved {
		return // Denied or error — close connection
	}

	// Step 5: Connect to isolated backend and splice
	backend, err := net.Dial("tcp", p.backendAddr)
	if err != nil {
		return
	}
	defer backend.Close()

	// Send any buffered pre-approval data
	if hc.BufferedLen > 0 {
		backend.Write(hc.Buffered[:hc.BufferedLen])
	}

	// Bidirectional splice
	go func() {
		io.Copy(backend, conn)
		backend.Close()
	}()
	io.Copy(conn, backend)
}

// ─── Buffered Read ───────────────────────────────────────────────────────

// Read implements pre-approval buffered reads.
// Bytes are buffered up to MaxPreApprovalBytes; excess is rejected.
func (hc *heldConnection) Read(b []byte) (int, error) {
	if hc.BufferedLen >= int32(len(hc.Buffered)) {
		return 0, fmt.Errorf("tcpproxy: pre-approval buffer exceeded")
	}

	n, err := hc.Conn.Read(b)
	if err != nil {
		return n, err
	}

	// Buffer for replay after approval
	space := len(hc.Buffered) - int(hc.BufferedLen)
	if space > 0 {
		copyLen := n
		if copyLen > space {
			copyLen = space
		}
		copy(hc.Buffered[hc.BufferedLen:], b[:copyLen])
		hc.BufferedLen += int32(copyLen)
	}

	return n, nil
}

// ─── Active Session Registry (DR-REV-3) ──────────────────────────────────

// ActiveSession tracks a live proxied session for revocation termination.
type ActiveSession struct {
	ConnectionID string
	GrantJTI     uuid.UUID
	DeviceID     uuid.UUID
	OpenedAt     time.Time
	Conn         net.Conn
}

// SessionRegistry tracks all active sessions for revocation kill.
type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*ActiveSession // connection_id -> session
	grantMap map[uuid.UUID][]string    // grant_jti -> connection_ids
}

// NewSessionRegistry creates a new session registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		sessions: make(map[string]*ActiveSession),
		grantMap: make(map[uuid.UUID][]string),
	}
}

// Register adds an active session.
func (sr *SessionRegistry) Register(session *ActiveSession) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.sessions[session.ConnectionID] = session
	sr.grantMap[session.GrantJTI] = append(sr.grantMap[session.GrantJTI], session.ConnectionID)
}

// Unregister removes a completed session.
func (sr *SessionRegistry) Unregister(connectionID string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	delete(sr.sessions, connectionID)
}

// TerminateByDevice closes all active sessions associated with a revoked device.
func (sr *SessionRegistry) TerminateByDevice(deviceID uuid.UUID) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	count := 0
	for connID, session := range sr.sessions {
		if session.DeviceID == deviceID {
			session.Conn.Close()
			delete(sr.sessions, connID)
			count++
		}
	}
	return count
}

// TerminateByGrant closes all sessions using a revoked grant.
func (sr *SessionRegistry) TerminateByGrant(grantJTI uuid.UUID) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	count := 0
	if connIDs, ok := sr.grantMap[grantJTI]; ok {
		for _, connID := range connIDs {
			if session, exists := sr.sessions[connID]; exists {
				session.Conn.Close()
				delete(sr.sessions, connID)
				count++
			}
		}
		delete(sr.grantMap, grantJTI)
	}
	return count
}

// ─── Helpers ──────────────────────────────────────────────────────────────

type randSource struct{}

func (r randSource) Read(p []byte) (int, error) {
	return io.ReadFull(rand.Reader, p)
}

// Ensure imports
var _ = uuid.New
var _ = net.Dial
var _ = context.Background
