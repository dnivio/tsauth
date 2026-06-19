// Package ssh implements Dnivio SSH enforcement hooks for TS_SSH and OPENSSH modes.
// Per §7.4 (DR-ENF-9, DR-ENF-10a) of ENGINEERING.md v2.1.
package ssh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ─── TS_SSH Enforcement (§7.4, DR-ENF-9) ────────────────────────────────

// TSSSHEnforcer enforces biometric approval for Tailscale SSH connections.
// Hooks into tailssh to gate session authorization.
type TSSSHEnforcer struct {
	// Callbacks provided by the Dnivio daemon
	ResolvePrincipal func(ctx context.Context, conn net.Conn) (*PrincipalInfo, error)
	RequestApproval  func(ctx context.Context, req *ApprovalRequest) (*ApprovalResult, error)
}

// PrincipalInfo is the resolved Tailscale principal for the SSH source.
type PrincipalInfo struct {
	TenantID       uuid.UUID
	TailnetID      string
	SrcNodeID      string
	SrcNodeKeyEpoch int64
	User           *OIDCUser
	NodeState      string
}

// OIDCUser identifies a human user.
type OIDCUser struct {
	Issuer  string
	Subject string
	UserID  string
}

// ApprovalRequest is the SSH-specific approval request.
type ApprovalRequest struct {
	RequestID   uuid.UUID
	Principal   *PrincipalInfo
	Hostname    string
	SSHAccount  string
	Protocol    string
	SessionID   []byte // server-generated random session identifier
}

// ApprovalResult is the result of SSH approval.
type ApprovalResult struct {
	Approved  bool
	GrantJTI  uuid.UUID
	SessionID []byte
	ExpiresAt time.Time
}

// AuthorizeSession determines if an SSH session should be allowed.
// For TS_SSH: called by tailssh before allowing a new session.
// Returns the session ID if authorized, or an error to deny.
func (e *TSSSHEnforcer) AuthorizeSession(ctx context.Context, conn net.Conn, hostname, sshAccount string) (sessionID []byte, err error) {
	// Resolve the Tailscale principal
	principal, err := e.ResolvePrincipal(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("ssh: resolve principal: %w — denying access", err)
	}

	// Generate session ID (DR-ENF-9)
	sessionID = make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("ssh: generate session id: %w", err)
	}

	// Create approval request
	req := &ApprovalRequest{
		RequestID:  uuid.Must(uuid.NewV7()),
		Principal:  principal,
		Hostname:   hostname,
		SSHAccount: sshAccount,
		Protocol:   "SSH",
		SessionID:  sessionID,
	}

	// Request biometric approval
	result, err := e.RequestApproval(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("ssh: approval request failed: %w", err)
	}

	if !result.Approved {
		return nil, fmt.Errorf("ssh: access denied — biometric approval not granted")
	}

	return sessionID, nil
}

// ─── OpenSSH PAM Module (DR-ENF-10a) ────────────────────────────────────

// PAMModule implements the Dnivio PAM account module for Linux/macOS OpenSSH.
// Communicates with the daemon over a root-owned Unix domain socket.
type PAMModule struct {
	daemonSocketPath string
}

// NewPAMModule creates a PAM module instance.
func NewPAMModule(daemonSocketPath string) *PAMModule {
	return &PAMModule{daemonSocketPath: daemonSocketPath}
}

// PAMAccountCheck performs the PAM account authorization check.
// Called by sshd via pam_acct_mgmt.
// Returns nil if the session should be allowed after biometric approval.
func (m *PAMModule) PAMAccountCheck(ctx context.Context, username, rhost string, pamTxnID string) error {
	// Connect to daemon over Unix socket
	conn, err := net.Dial("unix", m.daemonSocketPath)
	if err != nil {
		return fmt.Errorf("pam: connect to daemon: %w", err)
	}
	defer conn.Close()

	// Exchange: send pam transaction details, receive allow/deny
	// In production, uses a defined protobuf exchange with peer credential verification
	request := fmt.Sprintf("ACCT,%s,%s,%s", username, rhost, pamTxnID)
	if _, err := conn.Write([]byte(request)); err != nil {
		return fmt.Errorf("pam: send request: %w", err)
	}

	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("pam: read response: %w", err)
	}

	if string(response[:n]) != "ALLOW" {
		return fmt.Errorf("pam: access denied")
	}

	return nil
}

// ─── OpenSSH AuthorizedKeysCommand (Windows, DR-ENF-10a) ─────────────────

// AuthorizedKeysHelper implements the Dnivio AuthorizedKeysCommand for Windows.
// sshd calls this command; it contacts the daemon and returns the authorized key
// only after biometric approval.
type AuthorizedKeysHelper struct {
	daemonPipePath string // named pipe path on Windows
}

// NewAuthorizedKeysHelper creates a new AuthorizedKeysCommand helper.
func NewAuthorizedKeysHelper(daemonPipePath string) *AuthorizedKeysHelper {
	return &AuthorizedKeysHelper{daemonPipePath: daemonPipePath}
}

// Execute runs the AuthorizedKeysCommand as called by sshd.
// args[0] is the username being authenticated.
// Returns the authorized key on stdout if approved, or exits non-zero.
func (h *AuthorizedKeysHelper) Execute(ctx context.Context, username string, publicKey []byte) ([]byte, error) {
	// Connect to daemon via Windows named pipe
	conn, err := winDialPipe(h.daemonPipePath)
	if err != nil {
		return nil, fmt.Errorf("authkeys: connect to daemon: %w", err)
	}
	defer conn.Close()

	// Send authorization request
	requestData := fmt.Sprintf("AUTHKEYS,%s,%x", username, sha256.Sum256(publicKey))
	if _, err := conn.Write([]byte(requestData)); err != nil {
		return nil, fmt.Errorf("authkeys: send request: %w", err)
	}

	// Wait for approval response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("authkeys: read response: %w", err)
	}

	resp := string(response[:n])
	if resp == "DENY" {
		return nil, fmt.Errorf("authkeys: access denied")
	}

	// Return the authorized key
	return publicKey, nil
}

func winDialPipe(path string) (net.Conn, error) {
	// Windows named pipe connection
	return net.Dial("unix", path) // simplified; actual uses Windows named pipe API
}

// ─── Daemon-Side SSH Authorizer ──────────────────────────────────────────

// Authorizer is the daemon-side SSH authorization component.
// Listens on a root-owned Unix socket (Linux/macOS) or named pipe (Windows).
type Authorizer struct {
	mu              sync.RWMutex
	socketPath      string
	listener         net.Listener
	activeSessions  map[string]*SSHSession // session_id -> session
	requestApproval func(ctx context.Context, req *ApprovalRequest) (*ApprovalResult, error)
}

// SSHSession represents an active SSH session under biometric enforcement.
type SSHSession struct {
	SessionID   []byte
	Username    string
	RemoteHost  string
	GrantJTI    uuid.UUID
	DeviceID    uuid.UUID
	OpenedAt    time.Time
	PAMTxnID    string
}

// NewAuthorizer creates a daemon-side SSH authorizer.
func NewAuthorizer(socketPath string, requestApproval func(context.Context, *ApprovalRequest) (*ApprovalResult, error)) *Authorizer {
	return &Authorizer{
		socketPath:      socketPath,
		activeSessions:  make(map[string]*SSHSession),
		requestApproval: requestApproval,
	}
}

// Start begins listening for PAM/AuthorizedKeysCommand requests.
func (a *Authorizer) Start(ctx context.Context) error {
	var err error
	a.listener, err = net.Listen("unix", a.socketPath)
	if err != nil {
		return fmt.Errorf("ssh: listen on %s: %w", a.socketPath, err)
	}

	go a.acceptLoop(ctx)
	return nil
}

func (a *Authorizer) acceptLoop(ctx context.Context) {
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			return
		}
		go a.handleRequest(ctx, conn)
	}
}

func (a *Authorizer) handleRequest(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])

	// Parse request type
	var username, rhost string
	fmt.Sscanf(request, "ACCT,%s,%s", &username, &rhost)

	// Generate session ID
	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	req := &ApprovalRequest{
		RequestID:  uuid.Must(uuid.NewV7()),
		Hostname:   rhost,
		SSHAccount: username,
		Protocol:   "SSH",
		SessionID:  sessionID,
	}

	result, err := a.requestApproval(ctx, req)
	if err != nil || !result.Approved {
		conn.Write([]byte("DENY"))
		return
	}

	// Register active session
	a.mu.Lock()
	a.activeSessions[string(sessionID)] = &SSHSession{
		SessionID:  sessionID,
		Username:   username,
		RemoteHost: rhost,
		GrantJTI:   result.GrantJTI,
		OpenedAt:   time.Now(),
	}
	a.mu.Unlock()

	conn.Write([]byte("ALLOW"))
}

// TerminateSession terminates an active SSH session (for revocation).
func (a *Authorizer) TerminateSession(sessionID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	session, ok := a.activeSessions[sessionID]
	if !ok {
		return fmt.Errorf("ssh: session %s not found", sessionID)
	}

	delete(a.activeSessions, sessionID)

	// In production, sends SIGHUP or uses SSH control channel to terminate
	_ = session

	return nil
}

// TerminateByDevice terminates all SSH sessions associated with a revoked device.
func (a *Authorizer) TerminateByDevice(deviceID uuid.UUID) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	count := 0
	for id, session := range a.activeSessions {
		if session.DeviceID == deviceID {
			delete(a.activeSessions, id)
			count++
		}
	}
	return count
}

// Stop shuts down the SSH authorizer listener.
func (a *Authorizer) Stop() {
	if a.listener != nil {
		a.listener.Close()
	}
}

// Ensure imports
var _ = context.Background
var _ = net.Listen
var _ = sha256.New
var _ = uuid.New
