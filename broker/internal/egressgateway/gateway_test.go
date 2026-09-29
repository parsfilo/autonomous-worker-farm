package egressgateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func secretFile(t *testing.T, value string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "provider-secret")
	if err := os.WriteFile(filename, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func testConfig(t *testing.T, upstreamURL string) Config {
	t.Helper()
	return Config{
		RouteID:               "openai-main",
		Protocol:              "openai-responses",
		UpstreamBaseURL:       upstreamURL,
		WorkerAuthKind:        "bearer",
		WorkerAuthHeader:      "Authorization",
		AttemptTokenSHA256:    tokenHash("attempt-token"),
		UpstreamAuthKind:      "bearer",
		UpstreamAuthHeader:    "Authorization",
		ProviderSecretFile:    secretFile(t, "provider-secret"),
		AllowedModels:         []string{"gpt-test"},
		RequestPathPrefixes:   []string{"/v1/responses", "/v1/models"},
		MaxRequestBytes:       1 << 20,
		MaxResponseBytes:      1 << 20,
		MaxConcurrentRequests: 4,
		AllowPrivateUpstream:  true,
	}
}

func requestGateway(t *testing.T, handler http.Handler, method, target, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestGatewayRewritesAttemptCredentialToProviderSecret(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer provider-secret" {
			t.Fatalf("unexpected upstream authorization: %q", got)
		}
		if got := r.Header.Get("X-AWF-Route-ID"); got != "openai-main" {
			t.Fatalf("unexpected route id: %q", got)
		}
		if r.URL.Path != "/v1/responses" || r.URL.RawQuery != "trace=1" {
			t.Fatalf("unexpected upstream URL: %s", r.URL.String())
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "attempt-token") {
			t.Fatal("worker credential leaked into upstream body")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "must-not-leak=1")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"ok\":true}")
	}))
	defer upstream.Close()

	gateway, err := New(testConfig(t, upstream.URL), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}

	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses?trace=1",
		"attempt-token",
		[]byte(`{"model":"gpt-test","input":"hello"}`),
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("unexpected upstream hit count: %d", upstreamHits.Load())
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("gateway leaked upstream Set-Cookie")
	}
}

func TestGatewayRejectsWrongAttemptTokenBeforeUpstream(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gateway, err := New(testConfig(t, upstream.URL), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses",
		"wrong-token",
		[]byte(`{"model":"gpt-test"}`),
	)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("invalid attempt token reached upstream")
	}
}

func TestGatewayRejectsModelEscalation(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gateway, err := New(testConfig(t, upstream.URL), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses",
		"attempt-token",
		[]byte(`{"model":"gpt-unapproved"}`),
	)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("unapproved model reached upstream")
	}
}

func TestGatewayRejectsPathEscape(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gateway, err := New(testConfig(t, upstream.URL), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/admin",
		"attempt-token",
		[]byte(`{"model":"gpt-test"}`),
	)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("forbidden path reached upstream")
	}
}

func TestGatewayDoesNotFollowUpstreamRedirects(t *testing.T) {
	var redirectedHits atomic.Int32
	var upstream *httptest.Server
	upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirectedHits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, upstream.URL+"/redirected", http.StatusFound)
	}))
	defer upstream.Close()

	gateway, err := New(testConfig(t, upstream.URL), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses",
		"attempt-token",
		[]byte(`{"model":"gpt-test"}`),
	)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if redirectedHits.Load() != 0 {
		t.Fatal("gateway followed upstream redirect")
	}
}

func TestGatewayRejectsOversizedUpstreamResponse(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
	}))
	defer upstream.Close()

	cfg := testConfig(t, upstream.URL)
	cfg.MaxResponseBytes = 1024
	gateway, err := New(cfg, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses",
		"attempt-token",
		[]byte(`{"model":"gpt-test"}`),
	)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "EGRESS_RESPONSE_TOO_LARGE") {
		t.Fatalf("unexpected error body: %s", rec.Body.String())
	}
}

func TestGatewayRejectsPrivateUpstreamByDefault(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := testConfig(t, upstream.URL)
	cfg.AllowPrivateUpstream = false
	gateway, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses",
		"attempt-token",
		[]byte(`{"model":"gpt-test"}`),
	)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for private upstream, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGatewayEnforcesConcurrencyLimit(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "{}")
	}))
	defer upstream.Close()

	cfg := testConfig(t, upstream.URL)
	cfg.MaxConcurrentRequests = 1
	gateway, err := New(cfg, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstDone <- requestGateway(
			t,
			gateway.Handler(),
			http.MethodPost,
			"http://awf-egress/v1/responses",
			"attempt-token",
			[]byte(`{"model":"gpt-test"}`),
		)
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not reach upstream")
	}

	second := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses",
		"attempt-token",
		[]byte(`{"model":"gpt-test"}`),
	)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", second.Code)
	}

	close(release)
	select {
	case first := <-firstDone:
		if first.Code != http.StatusOK {
			t.Fatalf("first request failed: %d %s", first.Code, first.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not finish")
	}
}

func TestGatewaySupportsHeaderStyleAnthropicCredentialRewrite(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "provider-secret" {
			t.Fatalf("unexpected x-api-key: %q", got)
		}
		if got := r.Header.Get("Anthropic-Version"); got != "2023-06-01" {
			t.Fatalf("anthropic version header was not forwarded: %q", got)
		}
		_, _ = io.WriteString(w, "{}")
	}))
	defer upstream.Close()

	cfg := testConfig(t, upstream.URL)
	cfg.Protocol = "anthropic"
	cfg.WorkerAuthKind = "header"
	cfg.WorkerAuthHeader = "x-api-key"
	cfg.UpstreamAuthKind = "header"
	cfg.UpstreamAuthHeader = "x-api-key"
	cfg.RequestPathPrefixes = []string{"/v1/messages"}
	cfg.AllowedModels = []string{"claude-test"}

	gateway, err := New(cfg, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"http://awf-egress/v1/messages",
		bytes.NewReader([]byte(`{"model":"claude-test","max_tokens":64}`)),
	)
	req.Header.Set("x-api-key", "attempt-token")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGatewayRejectsWorldReadableProviderSecret(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	filename := filepath.Join(t.TempDir(), "provider-secret")
	if err := os.WriteFile(filename, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, upstream.URL)
	cfg.ProviderSecretFile = filename

	if _, err := New(cfg, upstream.Client()); err == nil {
		t.Fatal("expected world-readable provider secret file to be rejected")
	}
}

func TestHealthDoesNotRequireAttemptCredential(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	gateway, err := New(testConfig(t, upstream.URL), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://awf-egress/healthz", nil)
	rec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["status"] != "ready" {
		t.Fatalf("unexpected health payload: %v", payload)
	}
}

func TestGatewayRejectsPrefixConfusionPath(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	gateway, err := New(testConfig(t, upstream.URL), upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(
		t,
		gateway.Handler(),
		http.MethodPost,
		"http://awf-egress/v1/responses-admin",
		"attempt-token",
		[]byte("{\"model\":\"gpt-test\"}"),
	)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("prefix-confusion path reached upstream")
	}
}

func TestPublicIPRejectsNonPublicSpecialRanges(t *testing.T) {
	cases := []string{
		"10.0.0.1",
		"127.0.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"100.127.255.254",
		"198.18.0.1",
		"198.19.255.254",
		"::1",
		"fc00::1",
		"fe80::1",
	}
	for _, value := range cases {
		if publicIP(net.ParseIP(value)) {
			t.Fatalf("expected %s to be rejected as non-public", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(value)) {
			t.Fatalf("expected %s to be accepted as public", value)
		}
	}
}

func TestGatewayForcesTotalUpstreamTimeout(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := upstream.Client()
	client.Timeout = 0
	gateway, err := New(testConfig(t, upstream.URL), client)
	if err != nil {
		t.Fatal(err)
	}
	if gateway.client.Timeout != maxUpstreamDuration {
		t.Fatalf("gateway client timeout = %s, want %s", gateway.client.Timeout, maxUpstreamDuration)
	}
}
