// Package dnivio provides the Go SDK for Dnivio-protected HTTP services.
// Implements HTTP retry/redemption helpers for clients accessing Dnivio-protected resources.
// Per DR-ENF-8b and §6 of ENGINEERING.md v2.1.
package dnivio

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ─── Client ──────────────────────────────────────────────────────────────

// Client is an HTTP client that handles Dnivio biometric approval challenges.
// When a Dnivio-protected resource returns an authentication challenge,
// the client automatically polls for approval and retries the request.
type Client struct {
	httpClient    *http.Client
	pollInterval  time.Duration
	maxWaitTime   time.Duration
	trustBundle   *x509.CertPool // Dnivio daemon's TLS certificate pool
}

// ClientOption configures the Dnivio HTTP client.
type ClientOption func(*Client)

// WithPollInterval sets the interval between status polls.
func WithPollInterval(d time.Duration) ClientOption {
	return func(c *Client) { c.pollInterval = d }
}

// WithMaxWaitTime sets the maximum time to wait for approval.
func WithMaxWaitTime(d time.Duration) ClientOption {
	return func(c *Client) { c.maxWaitTime = d }
}

// WithTrustBundle sets the TLS trust bundle for the Dnivio daemon.
func WithTrustBundle(pool *x509.CertPool) ClientOption {
	return func(c *Client) { c.trustBundle = pool }
}

// WithBaseHTTPClient sets a custom base HTTP client.
func WithBaseHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = client }
}

// NewClient creates a new Dnivio-aware HTTP client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		pollInterval: 2 * time.Second,
		maxWaitTime:  60 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.trustBundle != nil {
		if c.httpClient.Transport == nil {
			c.httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: c.trustBundle,
				},
			}
		}
	}

	return c
}

// ─── Challenge/Response Flow (DR-ENF-8b) ────────────────────────────────

// Do performs an HTTP request with automatic Dnivio challenge handling.
// If the request triggers a biometric approval requirement, this method:
// 1. Receives the challenge response with poll/redeem URLs
// 2. Polls the status endpoint until approval or timeout
// 3. Retries the request with the redemption capability
// 4. Returns the final response
func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req.Body != nil && req.GetBody == nil {
		// Buffer the body for potential retry
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("dnivio: read request body: %w", err)
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnivio: request failed: %w", err)
	}

	// Check for Dnivio authentication challenge
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("X-Dnivio-Challenge")
		if challenge == "" {
			return resp, nil // Not a Dnivio challenge — return as-is
		}

		resp.Body.Close()

		// Handle the challenge
		finalResp, err := c.handleChallenge(ctx, req, resp)
		if err != nil {
			return nil, fmt.Errorf("dnivio: challenge handling: %w", err)
		}
		return finalResp, nil
	}

	return resp, nil
}

// handleChallenge polls for approval and retries the request.
func (c *Client) handleChallenge(ctx context.Context, req *http.Request, challengeResp *http.Response) (*http.Response, error) {
	// Parse the challenge response for polling info
	statusURL := challengeResp.Header.Get("X-Dnivio-Status-URL")
	redeemPath := challengeResp.Header.Get("X-Dnivio-Redeem-Path")

	if statusURL == "" {
		return nil, fmt.Errorf("no status URL in challenge response")
	}

	// Extract poll capability from cookies
	pollCap := extractCookie(challengeResp, "__Host-dnivio-poll")
	redeemCap := extractCookie(challengeResp, "__Host-dnivio-redeem")

	if pollCap == "" {
		return nil, fmt.Errorf("no poll capability cookie in challenge response")
	}

	// Poll for approval
	approved, err := c.pollForApproval(ctx, req.URL, statusURL, pollCap)
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}

	if !approved {
		return nil, fmt.Errorf("approval denied or timed out")
	}

	// Retry the request with redemption capability
	retryReq := req.Clone(ctx)
	if redeemPath != "" && redeemCap != "" {
		retryReq.AddCookie(&http.Cookie{
			Name:     "__Host-dnivio-redeem",
			Value:    redeemCap,
			Path:     redeemPath,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	}

	if req.GetBody != nil {
		body, _ := req.GetBody()
		retryReq.Body = body
	}

	return c.httpClient.Do(retryReq)
}

// pollForApproval polls the Dnivio status endpoint until approval, denial, or timeout.
func (c *Client) pollForApproval(ctx context.Context, baseURL *url.URL, statusPath, pollCap string) (bool, error) {
	statusURL := *baseURL
	statusURL.Path = statusPath

	deadline := time.Now().Add(c.maxWaitTime)

	pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL.String(), nil)
	if err != nil {
		return false, err
	}

	pollReq.AddCookie(&http.Cookie{
		Name:     "__Host-dnivio-poll",
		Value:    pollCap,
		Path:     statusPath,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return false, fmt.Errorf("approval polling timed out after %v", c.maxWaitTime)
			}

			resp, err := c.httpClient.Do(pollReq)
			if err != nil {
				continue // Retry on network errors
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			status := parseStatusResponse(body)
			switch status {
			case "APPROVED":
				return true, nil
			case "DENIED", "EXPIRED":
				return false, fmt.Errorf("approval %s", strings.ToLower(status))
			default:
				// PENDING — continue polling
			}
		}
	}
}

// ─── IDEMPOTENT OPERATIONS ───────────────────────────────────────────────

// DoIdempotent performs an idempotent request (GET/HEAD) with challenge handling.
// These requests are safe to retry without body concerns.
func (c *Client) DoIdempotent(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.Do(ctx, req)
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func extractCookie(resp *http.Response, name string) string {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func parseStatusResponse(body []byte) string {
	// Simple JSON parsing: {"status":"APPROVED"}
	s := string(body)
	if strings.Contains(s, `"APPROVED"`) {
		return "APPROVED"
	}
	if strings.Contains(s, `"DENIED"`) {
		return "DENIED"
	}
	if strings.Contains(s, `"EXPIRED"`) {
		return "EXPIRED"
	}
	return "PENDING"
}

// ─── Certificate Validation ──────────────────────────────────────────────

// VerifyDaemonCertificate validates the Dnivio daemon's TLS certificate.
func VerifyDaemonCertificate(cert *x509.Certificate, expectedNodeID string) error {
	if cert == nil {
		return fmt.Errorf("dnivio: nil certificate")
	}

	// Check that the certificate is for the expected protected node
	for _, san := range cert.DNSNames {
		if san == expectedNodeID {
			return nil
		}
	}

	for _, uri := range cert.URIs {
		if strings.Contains(uri.String(), expectedNodeID) {
			return nil
		}
	}

	return fmt.Errorf("dnivio: certificate node ID mismatch")
}

// Ensure imports
var _ = context.Background
var _ = http.StatusUnauthorized
var _ = time.Now
