package egressgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxSecretBytes      = 16 * 1024
	maxUpstreamDuration = 10 * time.Minute
)

var (
	idPattern   = regexp.MustCompile("^[a-z0-9][a-z0-9._-]{0,127}$")
	hashPattern = regexp.MustCompile("^[0-9a-f]{64}$")
)

type Config struct {
	RouteID               string
	Protocol              string
	UpstreamBaseURL       string
	WorkerAuthKind        string
	WorkerAuthHeader      string
	AttemptTokenSHA256    string
	UpstreamAuthKind      string
	UpstreamAuthHeader    string
	ProviderSecretFile    string
	AllowedModels         []string
	RequestPathPrefixes   []string
	MaxRequestBytes       int64
	MaxResponseBytes      int64
	MaxConcurrentRequests int
	AllowPrivateUpstream  bool
}

type Gateway struct {
	cfg              Config
	upstream         *url.URL
	providerSecret   string
	allowedModels    map[string]struct{}
	pathPrefixes     []string
	attemptTokenHash [sha256.Size]byte
	client           *http.Client
	slots            chan struct{}
}

func New(cfg Config, client *http.Client) (*Gateway, error) {
	if !idPattern.MatchString(cfg.RouteID) {
		return nil, errors.New("invalid route id")
	}
	switch cfg.Protocol {
	case "openai-responses", "openai-chat", "openai-compatible", "openai-compatible-responses", "anthropic":
	default:
		return nil, errors.New("unsupported gateway protocol")
	}
	upstream, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream base URL: %w", err)
	}
	if upstream.Scheme != "https" || upstream.Host == "" || upstream.User != nil ||
		upstream.RawQuery != "" || upstream.Fragment != "" ||
		(upstream.Path != "" && upstream.Path != "/") {
		return nil, errors.New("upstream base URL must be an HTTPS origin without path, query, fragment or userinfo")
	}
	if err := validateAuth(cfg.WorkerAuthKind, cfg.WorkerAuthHeader); err != nil {
		return nil, fmt.Errorf("worker auth: %w", err)
	}
	if err := validateAuth(cfg.UpstreamAuthKind, cfg.UpstreamAuthHeader); err != nil {
		return nil, fmt.Errorf("upstream auth: %w", err)
	}
	if !hashPattern.MatchString(cfg.AttemptTokenSHA256) {
		return nil, errors.New("attempt token SHA-256 must be 64 lowercase hex characters")
	}
	decodedHash, err := hex.DecodeString(cfg.AttemptTokenSHA256)
	if err != nil || len(decodedHash) != sha256.Size {
		return nil, errors.New("invalid attempt token SHA-256")
	}
	var tokenHash [sha256.Size]byte
	copy(tokenHash[:], decodedHash)

	if cfg.ProviderSecretFile == "" || !path.IsAbs(cfg.ProviderSecretFile) {
		return nil, errors.New("provider secret file must be an absolute path")
	}
	secret, err := readSecret(cfg.ProviderSecretFile)
	if err != nil {
		return nil, err
	}

	if cfg.MaxRequestBytes < 1024 || cfg.MaxRequestBytes > 128<<20 {
		return nil, errors.New("max request bytes outside accepted range")
	}
	if cfg.MaxResponseBytes < 1024 || cfg.MaxResponseBytes > 1<<30 {
		return nil, errors.New("max response bytes outside accepted range")
	}
	if cfg.MaxConcurrentRequests < 1 || cfg.MaxConcurrentRequests > 256 {
		return nil, errors.New("max concurrent requests outside accepted range")
	}
	if len(cfg.AllowedModels) == 0 || len(cfg.AllowedModels) > 128 {
		return nil, errors.New("allowed model set is empty or too large")
	}
	allowedModels := make(map[string]struct{}, len(cfg.AllowedModels))
	for _, model := range cfg.AllowedModels {
		if model == "" || len(model) > 256 {
			return nil, errors.New("invalid allowed model")
		}
		if _, exists := allowedModels[model]; exists {
			return nil, errors.New("duplicate allowed model")
		}
		allowedModels[model] = struct{}{}
	}

	if len(cfg.RequestPathPrefixes) == 0 || len(cfg.RequestPathPrefixes) > 32 {
		return nil, errors.New("request path prefix set is empty or too large")
	}
	pathPrefixes := make([]string, 0, len(cfg.RequestPathPrefixes))
	seenPrefixes := map[string]struct{}{}
	for _, prefix := range cfg.RequestPathPrefixes {
		if err := validatePathPrefix(prefix); err != nil {
			return nil, err
		}
		if _, exists := seenPrefixes[prefix]; exists {
			return nil, errors.New("duplicate request path prefix")
		}
		seenPrefixes[prefix] = struct{}{}
		pathPrefixes = append(pathPrefixes, prefix)
	}

	if client == nil {
		client = secureHTTPClient(cfg.AllowPrivateUpstream)
	} else {
		copied := *client
		copied.Timeout = maxUpstreamDuration
		copied.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client = &copied
	}

	return &Gateway{
		cfg:              cfg,
		upstream:         upstream,
		providerSecret:   secret,
		allowedModels:    allowedModels,
		pathPrefixes:     pathPrefixes,
		attemptTokenHash: tokenHash,
		client:           client,
		slots:            make(chan struct{}, cfg.MaxConcurrentRequests),
	}, nil
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{\"status\":\"ready\"}\n")
	})
	mux.HandleFunc("/", g.handleProxy)
	return mux
}

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !g.acquire() {
		writeGatewayError(w, http.StatusTooManyRequests, "EGRESS_CONCURRENCY_LIMIT")
		return
	}
	defer g.release()

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeGatewayError(w, http.StatusMethodNotAllowed, "EGRESS_METHOD_FORBIDDEN")
		return
	}
	if err := validateInboundPath(r.URL.Path, g.pathPrefixes); err != nil {
		writeGatewayError(w, http.StatusForbidden, "EGRESS_PATH_FORBIDDEN")
		return
	}
	if !g.authorized(r) {
		writeGatewayError(w, http.StatusUnauthorized, "EGRESS_ATTEMPT_TOKEN_INVALID")
		return
	}

	body, err := readBounded(r.Body, g.cfg.MaxRequestBytes)
	if err != nil {
		if errors.Is(err, errTooLarge) {
			writeGatewayError(w, http.StatusRequestEntityTooLarge, "EGRESS_REQUEST_TOO_LARGE")
			return
		}
		writeGatewayError(w, http.StatusBadRequest, "EGRESS_REQUEST_READ_FAILED")
		return
	}
	if r.Method == http.MethodPost {
		if err := g.validateModel(body); err != nil {
			writeGatewayError(w, http.StatusForbidden, "EGRESS_MODEL_FORBIDDEN")
			return
		}
	}

	target := *g.upstream
	target.Path = r.URL.Path
	target.RawPath = ""
	target.RawQuery = r.URL.RawQuery

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "EGRESS_UPSTREAM_REQUEST_INVALID")
		return
	}
	copySafeRequestHeaders(upstreamReq.Header, r.Header)
	setAuth(upstreamReq.Header, g.cfg.UpstreamAuthKind, g.cfg.UpstreamAuthHeader, g.providerSecret)
	upstreamReq.Header.Set("X-AWF-Route-ID", g.cfg.RouteID)

	response, err := g.client.Do(upstreamReq)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "EGRESS_UPSTREAM_UNAVAILABLE")
		return
	}
	defer response.Body.Close()

	if response.StatusCode >= 300 && response.StatusCode < 400 {
		writeGatewayError(w, http.StatusBadGateway, "EGRESS_UPSTREAM_REDIRECT_FORBIDDEN")
		return
	}
	responseBody, err := readBounded(response.Body, g.cfg.MaxResponseBytes)
	if err != nil {
		if errors.Is(err, errTooLarge) {
			writeGatewayError(w, http.StatusBadGateway, "EGRESS_RESPONSE_TOO_LARGE")
			return
		}
		writeGatewayError(w, http.StatusBadGateway, "EGRESS_RESPONSE_READ_FAILED")
		return
	}

	copySafeResponseHeaders(w.Header(), response.Header)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(responseBody)
}

func (g *Gateway) acquire() bool {
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *Gateway) release() {
	<-g.slots
}

func (g *Gateway) authorized(r *http.Request) bool {
	token, ok := extractAuthToken(r.Header, g.cfg.WorkerAuthKind, g.cfg.WorkerAuthHeader)
	if !ok {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], g.attemptTokenHash[:]) == 1
}

func (g *Gateway) validateModel(body []byte) error {
	if len(body) == 0 {
		return errors.New("POST body must contain JSON")
	}
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return errors.New("POST body must be JSON")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("POST body must contain one JSON value")
	}
	model, ok := payload["model"].(string)
	if !ok || model == "" {
		return errors.New("POST body must contain model")
	}
	if _, ok := g.allowedModels[model]; !ok {
		return errors.New("model is not allowed")
	}
	return nil
}

func validateAuth(kind, header string) error {
	if !validHeaderName(header) {
		return errors.New("invalid auth header name")
	}
	switch kind {
	case "bearer":
		if !strings.EqualFold(header, "Authorization") {
			return errors.New("bearer auth must use Authorization header")
		}
	case "header":
	default:
		return errors.New("auth kind must be bearer or header")
	}
	return nil
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

func validatePathPrefix(prefix string) error {
	if prefix == "" || len(prefix) > 256 || prefix[0] != '/' ||
		strings.Contains(prefix, "?") || strings.Contains(prefix, "#") ||
		strings.Contains(prefix, "\\") {
		return errors.New("invalid request path prefix")
	}
	if hasParentSegment(prefix) {
		return errors.New("request path prefix contains parent traversal")
	}
	return nil
}

func validateInboundPath(value string, prefixes []string) error {
	if value == "" || value[0] != '/' || strings.Contains(value, "\\") || hasParentSegment(value) {
		return errors.New("invalid inbound request path")
	}
	if path.Clean(value) != value && value != "/" {
		return errors.New("non-canonical inbound request path")
	}
	for _, prefix := range prefixes {
		if value == prefix {
			return nil
		}
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(value, prefix) {
				return nil
			}
			continue
		}
		if strings.HasPrefix(value, prefix+"/") {
			return nil
		}
	}
	return errors.New("request path is outside route allowlist")
}

func hasParentSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func extractAuthToken(headers http.Header, kind, headerName string) (string, bool) {
	values := headers.Values(headerName)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	switch kind {
	case "bearer":
		const prefix = "Bearer "
		if !strings.HasPrefix(value, prefix) {
			return "", false
		}
		token := strings.TrimSpace(strings.TrimPrefix(value, prefix))
		return token, token != ""
	case "header":
		return value, value != ""
	default:
		return "", false
	}
}

func setAuth(headers http.Header, kind, headerName, secret string) {
	headers.Del("Authorization")
	headers.Del(headerName)
	if kind == "bearer" {
		headers.Set(headerName, "Bearer "+secret)
		return
	}
	headers.Set(headerName, secret)
}

func copySafeRequestHeaders(dst, src http.Header) {
	for _, name := range []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta"} {
		for _, value := range src.Values(name) {
			dst.Add(name, value)
		}
	}
}

func copySafeResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		lower := strings.ToLower(name)
		if lower == "set-cookie" || lower == "location" || lower == "server" ||
			isHopByHopHeader(lower) {
			continue
		}
		if lower == "content-length" {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func isHopByHopHeader(lower string) bool {
	switch lower {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

var errTooLarge = errors.New("body exceeds configured limit")

func readBounded(reader io.Reader, max int64) ([]byte, error) {
	if reader == nil {
		return nil, nil
	}
	limited := io.LimitReader(reader, max+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errTooLarge
	}
	return data, nil
}

func readSecret(filename string) (string, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return "", fmt.Errorf("stat provider secret file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("provider secret path must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxSecretBytes {
		return "", errors.New("provider secret file size is invalid")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("provider secret file must not be group/world accessible")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("read provider secret file: %w", err)
	}
	data = bytes.TrimSuffix(data, []byte("\r\n"))
	data = bytes.TrimSuffix(data, []byte("\n"))
	if len(data) == 0 || bytes.IndexByte(data, 0) >= 0 {
		return "", errors.New("provider secret value is invalid")
	}
	return string(data), nil
}

func secureHTTPClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 180 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	if !allowPrivate {
		transport.DialContext = publicOnlyDialContext(dialer)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   maxUpstreamDuration,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func publicOnlyDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split upstream address: %w", err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid upstream port")
		}
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve upstream host: %w", err)
		}
		var lastErr error
		for _, addr := range addrs {
			if !publicIP(addr.IP) {
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), portText))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("upstream DNS resolved only to non-public addresses")
	}
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 || v4[0] == 127 || v4[0] >= 224 {
			return false
		}
		// RFC 6598 shared address space is not public Internet and may expose
		// carrier/provider-internal services.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		// RFC 2544 benchmarking range is non-public.
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}

func writeGatewayError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	payload, _ := json.Marshal(map[string]any{
		"error": map[string]string{
			"code": code,
		},
	})
	_, _ = w.Write(append(payload, '\n'))
}
