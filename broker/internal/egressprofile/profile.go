package egressprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const maxProfileBytes = 1 << 20

var (
	idPattern     = regexp.MustCompile("^[a-z0-9][a-z0-9._-]{0,127}$")
	digestPattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
	secretPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
)

type Image struct {
	Reference string
	Digest    string
}

type InternalNetwork struct {
	GatewayAlias       string
	LLMPort            int
	HTTPProxyPort      *int
	DirectEgressDenied bool
}

type Auth struct {
	Kind       string
	HeaderName string
}

type WorkerAuth struct {
	Kind       string
	HeaderName string
	SecretFile *string
}

type Route struct {
	RouteID             string
	ProviderID          string
	Protocol            string
	UpstreamBaseURL     string
	WorkerBasePath      string
	WorkerAuth          WorkerAuth
	UpstreamAuth        Auth
	SecretHandle        *string
	Models              []string
	RequestPathPrefixes []string
}

type PackageProxy struct {
	Enabled      bool
	AllowedHosts []string
	AllowedPorts []int
}

type Limits struct {
	MaxRequestBytes       int64
	MaxResponseBytes      int64
	MaxConcurrentRequests int
}

type Profile struct {
	SchemaVersion   string
	ProfileID       string
	Revision        int
	GatewayImage    Image
	InternalNetwork InternalNetwork
	Routes          []Route
	PackageProxy    PackageProxy
	Limits          Limits
	PolicyRevision  int
}

type Loaded struct {
	Profile Profile
	Hash    string
	Path    string
}

type Store struct {
	root        string
	requireRoot bool
}

func NewStore(root string, requireRoot bool) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("egress profile root must be absolute")
	}
	return &Store{root: filepath.Clean(root), requireRoot: requireRoot}, nil
}

func (s *Store) verifyRoot() error {
	info, err := os.Lstat(s.root)
	if err != nil {
		return fmt.Errorf("stat egress profile root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("egress profile root must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return fmt.Errorf("resolve egress profile root: %w", err)
	}
	if filepath.Clean(resolved) != s.root {
		return errors.New("egress profile root must not traverse symlinks")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("egress profile root must not be group/world writable")
	}
	if s.requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("production egress profile root must be root-owned")
		}
	}
	return nil
}

func (s *Store) Load(profileID string) (Loaded, error) {
	if err := s.verifyRoot(); err != nil {
		return Loaded{}, err
	}
	if !idPattern.MatchString(profileID) {
		return Loaded{}, errors.New("invalid egress profile id")
	}
	filename := filepath.Join(s.root, profileID+".json")
	if !under(s.root, filename) {
		return Loaded{}, errors.New("egress profile path escaped configured root")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return Loaded{}, fmt.Errorf("stat egress profile: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Loaded{}, errors.New("egress profile must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxProfileBytes {
		return Loaded{}, errors.New("egress profile size is invalid")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return Loaded{}, errors.New("egress profile must not be group/world writable")
	}
	if s.requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return Loaded{}, errors.New("production egress profile must be root-owned")
		}
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return Loaded{}, fmt.Errorf("read egress profile: %w", err)
	}
	profile, err := Decode(data)
	if err != nil {
		return Loaded{}, err
	}
	if profile.ProfileID != profileID {
		return Loaded{}, errors.New("egress profile id does not match filename")
	}
	return Loaded{
		Profile: profile,
		Hash:    BindingHash(profile),
		Path:    filename,
	}, nil
}

func Decode(data []byte) (Profile, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return Profile{}, fmt.Errorf("decode egress profile: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Profile{}, errors.New("egress profile must contain exactly one JSON value")
	}
	root, err := object(raw, "profile")
	if err != nil {
		return Profile{}, err
	}
	if err := exactKeys(root, "profile",
		"schema_version", "profile_id", "revision", "gateway_image",
		"internal_network", "routes", "package_proxy", "limits", "policy_revision",
	); err != nil {
		return Profile{}, err
	}

	var profile Profile
	if profile.SchemaVersion, err = stringField(root, "schema_version"); err != nil {
		return Profile{}, err
	}
	if profile.ProfileID, err = stringField(root, "profile_id"); err != nil {
		return Profile{}, err
	}
	if profile.Revision, err = intField(root, "revision"); err != nil {
		return Profile{}, err
	}
	if profile.GatewayImage, err = parseImage(root["gateway_image"]); err != nil {
		return Profile{}, err
	}
	if profile.InternalNetwork, err = parseInternalNetwork(root["internal_network"]); err != nil {
		return Profile{}, err
	}
	if profile.Routes, err = parseRoutes(root["routes"]); err != nil {
		return Profile{}, err
	}
	if profile.PackageProxy, err = parsePackageProxy(root["package_proxy"]); err != nil {
		return Profile{}, err
	}
	if profile.Limits, err = parseLimits(root["limits"]); err != nil {
		return Profile{}, err
	}
	if profile.PolicyRevision, err = intField(root, "policy_revision"); err != nil {
		return Profile{}, err
	}
	if err := Validate(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func Validate(profile Profile) error {
	if profile.SchemaVersion != "1.0" {
		return errors.New("unsupported egress profile schema version")
	}
	if !idPattern.MatchString(profile.ProfileID) || profile.Revision < 1 || profile.PolicyRevision < 1 {
		return errors.New("invalid egress profile identity/revision")
	}
	if profile.GatewayImage.Reference == "" ||
		strings.ContainsAny(profile.GatewayImage.Reference, " \t\r\n") ||
		!digestPattern.MatchString(profile.GatewayImage.Digest) {
		return errors.New("invalid egress gateway image")
	}
	if profile.InternalNetwork.GatewayAlias != "awf-egress" ||
		profile.InternalNetwork.LLMPort < 1024 ||
		profile.InternalNetwork.LLMPort > 65535 ||
		!profile.InternalNetwork.DirectEgressDenied {
		return errors.New("invalid internal egress network policy")
	}
	hasFreeConnectRoute := false
	for _, route := range profile.Routes {
		if route.Protocol == "opencode-free-connect" {
			hasFreeConnectRoute = true
			break
		}
	}
	if hasFreeConnectRoute && profile.InternalNetwork.HTTPProxyPort == nil {
		return errors.New("opencode-free-connect requires internal HTTP proxy port")
	}
	if !hasFreeConnectRoute && profile.InternalNetwork.HTTPProxyPort != nil {
		return errors.New("internal HTTP proxy port is reserved for opencode-free-connect")
	}
	if profile.PackageProxy.Enabled ||
		len(profile.PackageProxy.AllowedHosts) != 0 ||
		len(profile.PackageProxy.AllowedPorts) != 0 {
		return errors.New("phase 1 gateway does not implement generic package proxy")
	}
	if profile.Limits.MaxRequestBytes < 1024 || profile.Limits.MaxRequestBytes > 128<<20 ||
		profile.Limits.MaxResponseBytes < 1024 || profile.Limits.MaxResponseBytes > 1<<30 ||
		profile.Limits.MaxConcurrentRequests < 1 || profile.Limits.MaxConcurrentRequests > 256 {
		return errors.New("invalid egress limits")
	}
	if len(profile.Routes) == 0 || len(profile.Routes) > 32 {
		return errors.New("invalid egress route count")
	}
	routeIDs := map[string]struct{}{}
	for _, route := range profile.Routes {
		if err := validateRoute(route); err != nil {
			return err
		}
		if _, exists := routeIDs[route.RouteID]; exists {
			return errors.New("duplicate egress route id")
		}
		routeIDs[route.RouteID] = struct{}{}
	}
	return nil
}

func (l Loaded) Resolve(routeID, model string) (Route, error) {
	for _, route := range l.Profile.Routes {
		if route.RouteID != routeID {
			continue
		}
		if route.Protocol == "opencode-free-connect" {
			if len(route.Models) == 1 && route.Models[0] == "opencode/*" &&
				validOpenCodeModel(model) {
				return route, nil
			}
			return Route{}, errors.New("model is not allowed by selected egress route")
		}
		for _, allowed := range route.Models {
			if allowed == model {
				return route, nil
			}
		}
		return Route{}, errors.New("model is not allowed by selected egress route")
	}
	return Route{}, errors.New("egress route not found")
}

func BindingHash(profile Profile) string {
	var buf bytes.Buffer
	buf.WriteString("awf-egress-profile-v1\n")
	add := func(name, value string) {
		valueBytes := []byte(value)
		buf.WriteString(name)
		buf.WriteByte('=')
		buf.WriteString(strconv.Itoa(len(valueBytes)))
		buf.WriteByte(':')
		buf.Write(valueBytes)
		buf.WriteByte('\n')
	}

	add("schema_version", profile.SchemaVersion)
	add("profile_id", profile.ProfileID)
	add("revision", strconv.Itoa(profile.Revision))
	add("gateway_image.reference", profile.GatewayImage.Reference)
	add("gateway_image.digest", profile.GatewayImage.Digest)
	add("internal_network.gateway_alias", profile.InternalNetwork.GatewayAlias)
	add("internal_network.llm_port", strconv.Itoa(profile.InternalNetwork.LLMPort))
	if profile.InternalNetwork.HTTPProxyPort == nil {
		add("internal_network.http_proxy_port", "<null>")
	} else {
		add("internal_network.http_proxy_port", strconv.Itoa(*profile.InternalNetwork.HTTPProxyPort))
	}
	add("internal_network.direct_egress_denied", boolText(profile.InternalNetwork.DirectEgressDenied))

	add("routes.count", strconv.Itoa(len(profile.Routes)))
	for i, route := range profile.Routes {
		prefix := "routes." + strconv.Itoa(i) + "."
		add(prefix+"route_id", route.RouteID)
		add(prefix+"provider_id", route.ProviderID)
		add(prefix+"protocol", route.Protocol)
		add(prefix+"upstream_base_url", route.UpstreamBaseURL)
		add(prefix+"worker_base_path", route.WorkerBasePath)
		add(prefix+"worker_auth.kind", route.WorkerAuth.Kind)
		add(prefix+"worker_auth.header_name", route.WorkerAuth.HeaderName)
		if route.WorkerAuth.SecretFile == nil {
			add(prefix+"worker_auth.secret_file", "<null>")
		} else {
			add(prefix+"worker_auth.secret_file", *route.WorkerAuth.SecretFile)
		}
		add(prefix+"upstream_auth.kind", route.UpstreamAuth.Kind)
		add(prefix+"upstream_auth.header_name", route.UpstreamAuth.HeaderName)
		if route.SecretHandle == nil {
			add(prefix+"secret_handle", "<null>")
		} else {
			add(prefix+"secret_handle", *route.SecretHandle)
		}
		add(prefix+"models.count", strconv.Itoa(len(route.Models)))
		for j, model := range route.Models {
			add(prefix+"models."+strconv.Itoa(j), model)
		}
		add(prefix+"request_path_prefixes.count", strconv.Itoa(len(route.RequestPathPrefixes)))
		for j, routePrefix := range route.RequestPathPrefixes {
			add(prefix+"request_path_prefixes."+strconv.Itoa(j), routePrefix)
		}
	}

	add("package_proxy.enabled", boolText(profile.PackageProxy.Enabled))
	add("package_proxy.allowed_hosts.count", strconv.Itoa(len(profile.PackageProxy.AllowedHosts)))
	for i, host := range profile.PackageProxy.AllowedHosts {
		add("package_proxy.allowed_hosts."+strconv.Itoa(i), host)
	}
	add("package_proxy.allowed_ports.count", strconv.Itoa(len(profile.PackageProxy.AllowedPorts)))
	for i, port := range profile.PackageProxy.AllowedPorts {
		add("package_proxy.allowed_ports."+strconv.Itoa(i), strconv.Itoa(port))
	}

	add("limits.max_request_bytes", strconv.FormatInt(profile.Limits.MaxRequestBytes, 10))
	add("limits.max_response_bytes", strconv.FormatInt(profile.Limits.MaxResponseBytes, 10))
	add("limits.max_concurrent_requests", strconv.Itoa(profile.Limits.MaxConcurrentRequests))
	add("policy_revision", strconv.Itoa(profile.PolicyRevision))

	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func parseImage(value any) (Image, error) {
	m, err := object(value, "gateway_image")
	if err != nil {
		return Image{}, err
	}
	if err := exactKeys(m, "gateway_image", "reference", "digest"); err != nil {
		return Image{}, err
	}
	reference, err := stringField(m, "reference")
	if err != nil {
		return Image{}, err
	}
	digest, err := stringField(m, "digest")
	if err != nil {
		return Image{}, err
	}
	return Image{Reference: reference, Digest: digest}, nil
}

func parseInternalNetwork(value any) (InternalNetwork, error) {
	m, err := object(value, "internal_network")
	if err != nil {
		return InternalNetwork{}, err
	}
	if err := exactKeys(m, "internal_network",
		"gateway_alias", "llm_port", "http_proxy_port", "direct_egress_denied",
	); err != nil {
		return InternalNetwork{}, err
	}
	alias, err := stringField(m, "gateway_alias")
	if err != nil {
		return InternalNetwork{}, err
	}
	llmPort, err := intField(m, "llm_port")
	if err != nil {
		return InternalNetwork{}, err
	}
	httpProxyPort, err := nullableIntField(m, "http_proxy_port")
	if err != nil {
		return InternalNetwork{}, err
	}
	directDenied, err := boolField(m, "direct_egress_denied")
	if err != nil {
		return InternalNetwork{}, err
	}
	return InternalNetwork{
		GatewayAlias:       alias,
		LLMPort:            llmPort,
		HTTPProxyPort:      httpProxyPort,
		DirectEgressDenied: directDenied,
	}, nil
}

func parseRoutes(value any) ([]Route, error) {
	items, err := array(value, "routes")
	if err != nil {
		return nil, err
	}
	routes := make([]Route, 0, len(items))
	for i, item := range items {
		route, err := parseRoute(item, i)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func parseRoute(value any, index int) (Route, error) {
	label := "routes[" + strconv.Itoa(index) + "]"
	m, err := object(value, label)
	if err != nil {
		return Route{}, err
	}
	if err := exactKeys(m, label,
		"route_id", "provider_id", "protocol", "upstream_base_url", "worker_base_path",
		"worker_auth", "upstream_auth", "secret_handle", "models", "request_path_prefixes",
	); err != nil {
		return Route{}, err
	}

	routeID, err := stringField(m, "route_id")
	if err != nil {
		return Route{}, err
	}
	providerID, err := stringField(m, "provider_id")
	if err != nil {
		return Route{}, err
	}
	protocol, err := stringField(m, "protocol")
	if err != nil {
		return Route{}, err
	}
	upstream, err := stringField(m, "upstream_base_url")
	if err != nil {
		return Route{}, err
	}
	workerBasePath, err := stringField(m, "worker_base_path")
	if err != nil {
		return Route{}, err
	}
	workerAuth, err := parseWorkerAuth(m["worker_auth"])
	if err != nil {
		return Route{}, err
	}
	upstreamAuth, err := parseAuth(m["upstream_auth"], "upstream_auth")
	if err != nil {
		return Route{}, err
	}
	secretHandle, err := nullableStringField(m, "secret_handle")
	if err != nil {
		return Route{}, err
	}
	models, err := stringArray(m["models"], "models")
	if err != nil {
		return Route{}, err
	}
	prefixes, err := stringArray(m["request_path_prefixes"], "request_path_prefixes")
	if err != nil {
		return Route{}, err
	}
	return Route{
		RouteID:             routeID,
		ProviderID:          providerID,
		Protocol:            protocol,
		UpstreamBaseURL:     upstream,
		WorkerBasePath:      workerBasePath,
		WorkerAuth:          workerAuth,
		UpstreamAuth:        upstreamAuth,
		SecretHandle:        secretHandle,
		Models:              models,
		RequestPathPrefixes: prefixes,
	}, nil
}

func parseWorkerAuth(value any) (WorkerAuth, error) {
	m, err := object(value, "worker_auth")
	if err != nil {
		return WorkerAuth{}, err
	}
	if err := exactKeys(m, "worker_auth", "kind", "header_name", "secret_file"); err != nil {
		return WorkerAuth{}, err
	}
	kind, err := stringField(m, "kind")
	if err != nil {
		return WorkerAuth{}, err
	}
	header, err := stringField(m, "header_name")
	if err != nil {
		return WorkerAuth{}, err
	}
	secretFile, err := nullableStringField(m, "secret_file")
	if err != nil {
		return WorkerAuth{}, err
	}
	return WorkerAuth{Kind: kind, HeaderName: header, SecretFile: secretFile}, nil
}

func parseAuth(value any, label string) (Auth, error) {
	m, err := object(value, label)
	if err != nil {
		return Auth{}, err
	}
	if err := exactKeys(m, label, "kind", "header_name"); err != nil {
		return Auth{}, err
	}
	kind, err := stringField(m, "kind")
	if err != nil {
		return Auth{}, err
	}
	header, err := stringField(m, "header_name")
	if err != nil {
		return Auth{}, err
	}
	return Auth{Kind: kind, HeaderName: header}, nil
}

func parsePackageProxy(value any) (PackageProxy, error) {
	m, err := object(value, "package_proxy")
	if err != nil {
		return PackageProxy{}, err
	}
	if err := exactKeys(m, "package_proxy", "enabled", "allowed_hosts", "allowed_ports"); err != nil {
		return PackageProxy{}, err
	}
	enabled, err := boolField(m, "enabled")
	if err != nil {
		return PackageProxy{}, err
	}
	hosts, err := stringArray(m["allowed_hosts"], "allowed_hosts")
	if err != nil {
		return PackageProxy{}, err
	}
	ports, err := intArray(m["allowed_ports"], "allowed_ports")
	if err != nil {
		return PackageProxy{}, err
	}
	return PackageProxy{Enabled: enabled, AllowedHosts: hosts, AllowedPorts: ports}, nil
}

func parseLimits(value any) (Limits, error) {
	m, err := object(value, "limits")
	if err != nil {
		return Limits{}, err
	}
	if err := exactKeys(m, "limits", "max_request_bytes", "max_response_bytes", "max_concurrent_requests"); err != nil {
		return Limits{}, err
	}
	requestBytes, err := int64Field(m, "max_request_bytes")
	if err != nil {
		return Limits{}, err
	}
	responseBytes, err := int64Field(m, "max_response_bytes")
	if err != nil {
		return Limits{}, err
	}
	concurrent, err := intField(m, "max_concurrent_requests")
	if err != nil {
		return Limits{}, err
	}
	return Limits{
		MaxRequestBytes:       requestBytes,
		MaxResponseBytes:      responseBytes,
		MaxConcurrentRequests: concurrent,
	}, nil
}

func validateRoute(route Route) error {
	if !idPattern.MatchString(route.RouteID) || !idPattern.MatchString(route.ProviderID) {
		return errors.New("invalid egress route/provider id")
	}
	switch route.Protocol {
	case "openai-responses", "openai-chat", "openai-compatible", "openai-compatible-responses", "anthropic", "opencode-free-connect":
	default:
		return errors.New("unsupported egress route protocol")
	}
	upstream, err := url.Parse(route.UpstreamBaseURL)
	if err != nil ||
		upstream.Scheme != "https" ||
		upstream.Host == "" ||
		upstream.User != nil ||
		upstream.RawQuery != "" ||
		upstream.Fragment != "" ||
		(upstream.Path != "" && upstream.Path != "/") {
		return errors.New("egress upstream must be an HTTPS origin")
	}
	if err := validateBasePath(route.WorkerBasePath); err != nil {
		return err
	}

	models := map[string]struct{}{}
	for _, model := range route.Models {
		if model == "" || len(model) > 256 {
			return errors.New("invalid egress model")
		}
		if _, exists := models[model]; exists {
			return errors.New("duplicate egress model")
		}
		models[model] = struct{}{}
	}

	if route.Protocol == "opencode-free-connect" {
		if route.RouteID != "opencode-free" ||
			route.ProviderID != "opencode" ||
			route.UpstreamBaseURL != "https://opencode.ai" ||
			route.WorkerBasePath != "/" ||
			route.WorkerAuth.Kind != "none" ||
			route.WorkerAuth.HeaderName != "" ||
			route.WorkerAuth.SecretFile != nil ||
			route.UpstreamAuth.Kind != "none" ||
			route.UpstreamAuth.HeaderName != "" ||
			route.SecretHandle != nil ||
			len(route.Models) != 1 ||
			route.Models[0] != "opencode/*" ||
			len(route.RequestPathPrefixes) != 0 {
			return errors.New("opencode-free-connect route must be anonymous, secretless, host-pinned and namespace-limited")
		}
		return nil
	}

	if err := validateAuth(route.WorkerAuth.Kind, route.WorkerAuth.HeaderName); err != nil {
		return err
	}
	if route.WorkerAuth.Kind == "none" {
		return errors.New("secret-backed worker auth cannot use none")
	}
	if route.WorkerAuth.SecretFile == nil || *route.WorkerAuth.SecretFile != "/run/egress/attempt-token" {
		return errors.New("worker egress secret file must use the fixed path")
	}
	if err := validateAuth(route.UpstreamAuth.Kind, route.UpstreamAuth.HeaderName); err != nil {
		return err
	}
	if route.UpstreamAuth.Kind == "none" {
		return errors.New("secret-backed upstream auth cannot use none")
	}
	if route.SecretHandle == nil ||
		!secretPattern.MatchString(*route.SecretHandle) ||
		!validSecretHandle(*route.SecretHandle) {
		return errors.New("invalid egress secret handle")
	}
	if len(route.Models) == 0 || len(route.Models) > 128 {
		return errors.New("invalid egress model count")
	}
	if len(route.RequestPathPrefixes) == 0 || len(route.RequestPathPrefixes) > 32 {
		return errors.New("invalid egress request path prefix count")
	}
	prefixes := map[string]struct{}{}
	for _, routePrefix := range route.RequestPathPrefixes {
		if err := validateBasePath(routePrefix); err != nil {
			return errors.New("invalid egress request path prefix")
		}
		if _, exists := prefixes[routePrefix]; exists {
			return errors.New("duplicate egress request path prefix")
		}
		prefixes[routePrefix] = struct{}{}
	}
	return nil
}

func validOpenCodeModel(value string) bool {
	if !strings.HasPrefix(value, "opencode/") || len(value) > 256 {
		return false
	}
	model := strings.TrimPrefix(value, "opencode/")
	if model == "" {
		return false
	}
	for _, r := range model {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validSecretHandle(value string) bool {
	const prefix = "secret://"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	relative := strings.TrimPrefix(value, prefix)
	parts := strings.Split(relative, "/")
	if len(parts) == 0 {
		return false
	}
	component := regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
	for _, part := range parts {
		if !component.MatchString(part) {
			return false
		}
	}
	return true
}

func validateAuth(kind, headerName string) error {
	if kind == "none" {
		if headerName != "" {
			return errors.New("none egress auth must use empty header")
		}
		return nil
	}
	if !validHeaderName(headerName) {
		return errors.New("invalid egress auth header")
	}
	switch kind {
	case "bearer":
		if !strings.EqualFold(headerName, "Authorization") {
			return errors.New("bearer egress auth must use Authorization header")
		}
	case "header":
	default:
		return errors.New("invalid egress auth kind")
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

func validateBasePath(value string) error {
	if value == "" || value[0] != '/' || strings.ContainsAny(value, "\\?#") ||
		path.Clean(value) != value {
		return errors.New("egress path must be canonical")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return errors.New("egress path contains parent traversal")
		}
	}
	return nil
}

func object(value any, label string) (map[string]any, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	return m, nil
}

func array(value any, label string) ([]any, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	return items, nil
}

func exactKeys(m map[string]any, label string, keys ...string) error {
	expected := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		expected[key] = struct{}{}
		if _, exists := m[key]; !exists {
			return fmt.Errorf("%s missing required field %s", label, key)
		}
	}
	for key := range m {
		if _, exists := expected[key]; !exists {
			return fmt.Errorf("%s contains unknown field %s", label, key)
		}
	}
	return nil
}

func stringField(m map[string]any, key string) (string, error) {
	value, ok := m[key].(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return value, nil
}

func nullableStringField(m map[string]any, key string) (*string, error) {
	if m[key] == nil {
		return nil, nil
	}
	value, err := stringField(m, key)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func boolField(m map[string]any, key string) (bool, error) {
	value, ok := m[key].(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return value, nil
}

func intField(m map[string]any, key string) (int, error) {
	value, err := int64Field(m, key)
	if err != nil {
		return 0, err
	}
	converted := int(value)
	if int64(converted) != value {
		return 0, fmt.Errorf("%s is outside int range", key)
	}
	return converted, nil
}

func int64Field(m map[string]any, key string) (int64, error) {
	number, ok := m[key].(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	value, err := strconv.ParseInt(string(number), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return value, nil
}

func nullableIntField(m map[string]any, key string) (*int, error) {
	if m[key] == nil {
		return nil, nil
	}
	value, err := intField(m, key)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func stringArray(value any, label string) ([]string, error) {
	items, err := array(value, label)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", label, i)
		}
		result = append(result, text)
	}
	return result, nil
}

func intArray(value any, label string) ([]int, error) {
	items, err := array(value, label)
	if err != nil {
		return nil, err
	}
	result := make([]int, 0, len(items))
	for i, item := range items {
		number, ok := item.(json.Number)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an integer", label, i)
		}
		parsed, err := strconv.ParseInt(string(number), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s[%d] must be an integer", label, i)
		}
		result = append(result, int(parsed))
	}
	return result, nil
}

func boolText(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func under(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}
