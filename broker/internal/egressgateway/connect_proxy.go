package egressgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultConnectDialTimeout = 10 * time.Second
	defaultTunnelLifetime     = 10 * time.Minute
)

type IPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type ConnectProxyConfig struct {
	AllowedHost           string
	AllowedPort           int
	MaxConcurrentRequests int
	AllowPrivateUpstream  bool
	DialTimeout           time.Duration
	TunnelLifetime        time.Duration
}

type ConnectProxy struct {
	cfg      ConnectProxyConfig
	resolver IPResolver
	dial     DialContextFunc
	slots    chan struct{}
}

func NewConnectProxy(
	cfg ConnectProxyConfig,
	resolver IPResolver,
	dial DialContextFunc,
) (*ConnectProxy, error) {
	if !strings.EqualFold(cfg.AllowedHost, "opencode.ai") {
		return nil, errors.New("free-model CONNECT proxy host must be opencode.ai")
	}
	if cfg.AllowedPort != 443 {
		return nil, errors.New("free-model CONNECT proxy port must be 443")
	}
	if cfg.MaxConcurrentRequests < 1 || cfg.MaxConcurrentRequests > 256 {
		return nil, errors.New("CONNECT proxy concurrency outside accepted range")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultConnectDialTimeout
	}
	if cfg.TunnelLifetime <= 0 {
		cfg.TunnelLifetime = defaultTunnelLifetime
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dial == nil {
		dialer := &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	return &ConnectProxy{
		cfg:      cfg,
		resolver: resolver,
		dial:     dial,
		slots:    make(chan struct{}, cfg.MaxConcurrentRequests),
	}, nil
}

func (p *ConnectProxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{\"status\":\"ready\"}\n")
			return
		}
		p.handle(w, r)
	})
}

func (p *ConnectProxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", "CONNECT")
		writeGatewayError(w, http.StatusMethodNotAllowed, "EGRESS_CONNECT_REQUIRED")
		return
	}
	if !p.acquire() {
		writeGatewayError(w, http.StatusTooManyRequests, "EGRESS_CONCURRENCY_LIMIT")
		return
	}
	defer p.release()

	host, portText, err := net.SplitHostPort(r.Host)
	if err != nil {
		writeGatewayError(w, http.StatusBadRequest, "EGRESS_CONNECT_TARGET_INVALID")
		return
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != p.cfg.AllowedPort || !strings.EqualFold(host, p.cfg.AllowedHost) {
		writeGatewayError(w, http.StatusForbidden, "EGRESS_CONNECT_TARGET_FORBIDDEN")
		return
	}

	address, err := p.resolveDialAddress(r.Context(), host, port)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "EGRESS_UPSTREAM_UNAVAILABLE")
		return
	}
	upstream, err := p.dial(r.Context(), "tcp", address)
	if err != nil {
		writeGatewayError(w, http.StatusBadGateway, "EGRESS_UPSTREAM_UNAVAILABLE")
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeGatewayError(w, http.StatusInternalServerError, "EGRESS_HIJACK_UNAVAILABLE")
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	deadline := time.Now().Add(p.cfg.TunnelLifetime)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// Hijack may leave bytes that arrived immediately after the CONNECT
		// headers buffered in the server reader (for example a TLS ClientHello).
		// Copy from the buffered reader, not the raw socket, or those bytes are lost.
		_, _ = io.Copy(upstream, buffered.Reader)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	wg.Wait()
}

func (p *ConnectProxy) resolveDialAddress(
	ctx context.Context,
	host string,
	port int,
) (string, error) {
	addresses, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve CONNECT host: %w", err)
	}
	if len(addresses) == 0 {
		return "", errors.New("CONNECT host resolved to no addresses")
	}
	var firstPublic net.IP
	for _, address := range addresses {
		if !p.cfg.AllowPrivateUpstream && !publicIP(address.IP) {
			return "", errors.New("CONNECT host resolved to non-public address")
		}
		if firstPublic == nil {
			firstPublic = address.IP
		}
	}
	if firstPublic == nil {
		return "", errors.New("CONNECT host has no accepted address")
	}
	return net.JoinHostPort(firstPublic.String(), strconv.Itoa(port)), nil
}

func (p *ConnectProxy) acquire() bool {
	select {
	case p.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *ConnectProxy) release() {
	<-p.slots
}
