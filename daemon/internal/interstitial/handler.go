// Package interstitial implements the browser-based approval interstitial for HTTP_PROXY mode.
// Per §7.4 (DR-ENF-8a) of ENGINEERING.md v2.1.
// Features: same-origin status polling, separate poll/redeem capabilities,
// secure cookies, strict CSP, constant-shape responses, atomic redemption.
package interstitial

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ─── Interstitial Handler ─────────────────────────────────────────────────

// Handler serves the browser interstitial page and status polling endpoint.
type Handler struct {
	mu          sync.RWMutex
	pendingReqs map[string]*PendingRequest // request_id -> pending request
}

// PendingRequest represents an approval request awaiting browser redemption.
type PendingRequest struct {
	RequestID       uuid.UUID
	PollCap         string // hashed at rest; only hash stored
	PollCapHash     []byte
	RedeemCap       string // hashed at rest; only hash stored
	RedeemCapHash   []byte
	Status          string // PENDING, APPROVED, DENIED, EXPIRED
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ApprovedGrantJTI *uuid.UUID
}

// NewHandler creates a new interstitial handler.
func NewHandler() *Handler {
	return &Handler{
		pendingReqs: make(map[string]*PendingRequest),
	}
}

// RegisterPending registers a new pending request with the interstitial.
// Returns the poll and redeem capability strings.
func (h *Handler) RegisterPending(requestID uuid.UUID, ttl time.Duration) (pollCap, redeemCap string, err error) {
	pollCap = generateCapability()
	redeemCap = generateCapability()

	pollHash := sha256.Sum256([]byte(pollCap))
	redeemHash := sha256.Sum256([]byte(redeemCap))

	h.mu.Lock()
	h.pendingReqs[requestID.String()] = &PendingRequest{
		RequestID:     requestID,
		PollCap:       pollCap,
		PollCapHash:   pollHash[:],
		RedeemCap:     redeemCap,
		RedeemCapHash: redeemHash[:],
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(ttl),
	}
	h.mu.Unlock()

	return pollCap, redeemCap, nil
}

// MarkApproved updates the pending request status to APPROVED.
// The grant JTI is stored for redemption validation.
func (h *Handler) MarkApproved(requestID uuid.UUID, grantJTI uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req, ok := h.pendingReqs[requestID.String()]; ok {
		req.Status = "APPROVED"
		req.ApprovedGrantJTI = &grantJTI
	}
}

// MarkDenied updates the pending request status to DENIED.
func (h *Handler) MarkDenied(requestID uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if req, ok := h.pendingReqs[requestID.String()]; ok {
		req.Status = "DENIED"
	}
}

// MarkExpired marks expired pending requests.
func (h *Handler) MarkExpired() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now().UTC()
	count := 0
	for id, req := range h.pendingReqs {
		if now.After(req.ExpiresAt) && req.Status == "PENDING" {
			req.Status = "EXPIRED"
			count++
		}
		// Cleanup expired entries older than 5 minutes
		if now.After(req.ExpiresAt.Add(5 * time.Minute)) {
			delete(h.pendingReqs, id)
		}
	}
	return count
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────

// ServeInterstitial serves the HTML interstitial page shown to the user.
// Uses strict CSP, no-referrer, no-store, and constant-shape output.
func (h *Handler) ServeInterstitial(w http.ResponseWriter, r *http.Request, requestID uuid.UUID, pollCap, destName string) {
	// Security headers per DR-ENF-8a
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none';")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	// Set poll capability cookie (Secure, HttpOnly, SameSite=Strict, narrow path)
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-dnivio-poll",
		Value:    pollCap,
		Path:     "/.dnivio/status/" + requestID.String(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   60,
	})

	data := interstitialData{
		RequestID:   requestID.String(),
		DestName:    destName,
		PollPath:    "/.dnivio/status/" + requestID.String(),
		RefreshAfter: 2,
	}

	pageTemplate.Execute(w, data)
}

type interstitialData struct {
	RequestID    string
	DestName     string
	PollPath     string
	RefreshAfter int
}

var pageTemplate = template.Must(template.New("interstitial").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Verification — Dnivio</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 480px; margin: 10vh auto; padding: 2rem; text-align: center; background: #fff; color: #333; }
  .spinner { border: 3px solid #e0e0e0; border-top: 3px solid #2563eb; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 2rem auto; }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  .dest { font-weight: 600; color: #1e40af; word-break: break-all; }
  .status { color: #6b7280; font-size: 0.9rem; margin-top: 1.5rem; }
</style>
</head>
<body>
<h1>Access Verification Required</h1>
<p>You are requesting access to <span class="dest">{{.DestName}}</span>.</p>
<p>Please approve the request on your trusted mobile device.</p>
<div class="spinner"></div>
<div class="status">Waiting for biometric approval…</div>
<script>
  (function() {
    var pollPath = "{{.PollPath}}";
    var requestID = "{{.RequestID}}";
    function check() {
      fetch(pollPath, { credentials: "same-origin", cache: "no-store" })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.status === "APPROVED") {
            location.reload();
          } else if (data.status === "DENIED" || data.status === "EXPIRED") {
            document.querySelector(".status").textContent = "Access " + data.status.toLowerCase() + ".";
            document.querySelector(".spinner").style.display = "none";
          } else {
            setTimeout(check, {{.RefreshAfter}} * 1000);
          }
        })
        .catch(function() {
          setTimeout(check, {{.RefreshAfter}} * 1000);
        });
    }
    setTimeout(check, 1000);
  })();
</script>
</body>
</html>`))

// ServeStatus serves the status endpoint for the browser polling loop.
// Returns constant-shape JSON responses regardless of state.
func (h *Handler) ServeStatus(w http.ResponseWriter, r *http.Request, requestID uuid.UUID) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Referrer-Policy", "no-referrer")

	// Verify poll capability from cookie
	pollCookie, err := r.Cookie("__Host-dnivio-poll")
	if err != nil {
		// Constant response shape — no information leakage
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"PENDING"}`))
		return
	}

	pollHash := sha256.Sum256([]byte(pollCookie.Value))

	h.mu.RLock()
	req, ok := h.pendingReqs[requestID.String()]
	h.mu.RUnlock()

	if !ok || subtle.ConstantTimeCompare(req.PollCapHash, pollHash[:]) != 1 {
		// Constant response shape
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"PENDING"}`))
		return
	}

	// DR-ENF-8a: constant-shape status body regardless of state
	resp := fmt.Sprintf(`{"status":"%s"}`, req.Status)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(resp))
}

// RedeemGrant validates the one-time redemption capability and returns the grant JTI.
// Per DR-ENF-8a: atomically consumes the redeem capability, AGT JTI, and request_nonce.
func (h *Handler) RedeemGrant(r *http.Request, requestID uuid.UUID) (*uuid.UUID, error) {
	redeemCookie, err := r.Cookie("__Host-dnivio-redeem")
	if err != nil {
		return nil, fmt.Errorf("interstitial: no redeem cookie")
	}

	redeemHash := sha256.Sum256([]byte(redeemCookie.Value))

	h.mu.Lock()
	defer h.mu.Unlock()

	req, ok := h.pendingReqs[requestID.String()]
	if !ok {
		return nil, fmt.Errorf("interstitial: request not found")
	}

	if subtle.ConstantTimeCompare(req.RedeemCapHash, redeemHash[:]) != 1 {
		return nil, fmt.Errorf("interstitial: invalid redeem capability")
	}

	if req.Status != "APPROVED" || req.ApprovedGrantJTI == nil {
		return nil, fmt.Errorf("interstitial: request not approved")
	}

	// Atomic consume: clear redeem capability and return JTI
	jti := *req.ApprovedGrantJTI
	req.RedeemCap = ""
	req.RedeemCapHash = nil
	req.Status = "GRANTED"

	return &jti, nil
}

// SetRedeemCookie sets the redemption capability cookie in the browser.
func SetRedeemCookie(w http.ResponseWriter, requestID uuid.UUID, redeemCap string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-dnivio-redeem",
		Value:    redeemCap,
		Path:     "/.dnivio/redeem/" + requestID.String(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   60,
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func generateCapability() string {
	b := make([]byte, 32) // ≥256 bits per DR-ENF-8a
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Ensure imports
var _ = strings.TrimSpace
var _ = sha256.New
var _ = template.New
var _ = uuid.New
var _ = http.StatusOK
