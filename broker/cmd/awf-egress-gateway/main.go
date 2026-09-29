package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"autonomous-worker/broker/internal/egressgateway"
)

type stringList []string

func (s *stringList) String() string {
	return fmt.Sprintf("%v", []string(*s))
}

func (s *stringList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("value must not be empty")
	}
	*s = append(*s, value)
	return nil
}

func main() {
	var (
		mode               = flag.String("mode", "provider", "gateway mode: provider or opencode-free-connect")
		listenAddress      = flag.String("listen", ":8443", "internal gateway listen address")
		routeID            = flag.String("route-id", "", "trusted egress route identifier")
		protocol           = flag.String("protocol", "", "provider protocol")
		upstreamBaseURL    = flag.String("upstream-base-url", "", "fixed HTTPS upstream origin")
		workerAuthKind     = flag.String("worker-auth-kind", "", "worker auth kind: bearer or header")
		workerAuthHeader   = flag.String("worker-auth-header", "", "worker credential header")
		attemptTokenSHA256 = flag.String("attempt-token-sha256", "", "SHA-256 of attempt-scoped worker token")
		upstreamAuthKind   = flag.String("upstream-auth-kind", "", "upstream provider auth kind")
		upstreamAuthHeader = flag.String("upstream-auth-header", "", "upstream provider auth header")
		providerSecretFile = flag.String("provider-secret-file", "", "read-only provider secret file")
		maxRequestBytes    = flag.Int64("max-request-bytes", 8<<20, "maximum worker request body bytes")
		maxResponseBytes   = flag.Int64("max-response-bytes", 64<<20, "maximum upstream response body bytes")
		maxConcurrent      = flag.Int("max-concurrent-requests", 8, "maximum concurrent upstream requests")
		proxyHost          = flag.String("proxy-host", "opencode.ai", "CONNECT proxy allowed host")
		proxyPort          = flag.Int("proxy-port", 443, "CONNECT proxy allowed port")
	)
	var allowedModels stringList
	var pathPrefixes stringList
	flag.Var(&allowedModels, "allowed-model", "allowed provider model; may be repeated")
	flag.Var(&pathPrefixes, "path-prefix", "allowed upstream request path prefix; may be repeated")
	flag.Parse()

	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "egress gateway refuses to run as root")
		os.Exit(2)
	}

	var handler http.Handler
	switch *mode {
	case "provider":
		gateway, err := egressgateway.New(egressgateway.Config{
			RouteID:               *routeID,
			Protocol:              *protocol,
			UpstreamBaseURL:       *upstreamBaseURL,
			WorkerAuthKind:        *workerAuthKind,
			WorkerAuthHeader:      *workerAuthHeader,
			AttemptTokenSHA256:    *attemptTokenSHA256,
			UpstreamAuthKind:      *upstreamAuthKind,
			UpstreamAuthHeader:    *upstreamAuthHeader,
			ProviderSecretFile:    *providerSecretFile,
			AllowedModels:         []string(allowedModels),
			RequestPathPrefixes:   []string(pathPrefixes),
			MaxRequestBytes:       *maxRequestBytes,
			MaxResponseBytes:      *maxResponseBytes,
			MaxConcurrentRequests: *maxConcurrent,
			AllowPrivateUpstream:  false,
		}, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		handler = gateway.Handler()
	case "opencode-free-connect":
		proxy, err := egressgateway.NewConnectProxy(egressgateway.ConnectProxyConfig{
			AllowedHost:           *proxyHost,
			AllowedPort:           *proxyPort,
			MaxConcurrentRequests: *maxConcurrent,
			AllowPrivateUpstream:  false,
		}, nil, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		handler = proxy.Handler()
	default:
		fmt.Fprintln(os.Stderr, "unsupported gateway mode")
		os.Exit(2)
	}

	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
