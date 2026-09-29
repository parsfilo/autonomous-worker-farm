package egressgateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type staticResolver struct {
	addresses []net.IPAddr
	err       error
}

func (r staticResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return r.addresses, r.err
}

func TestConnectProxyRejectsNonConnectAndWrongTarget(t *testing.T) {
	proxy, err := NewConnectProxy(ConnectProxyConfig{
		AllowedHost:           "opencode.ai",
		AllowedPort:           443,
		MaxConcurrentRequests: 2,
		AllowPrivateUpstream:  true,
	}, staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://awf-egress/", nil)
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong host status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodConnect, "http://opencode.ai:8443", nil)
	req.Host = "opencode.ai:8443"
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong port status = %d, want 403", rec.Code)
	}
}

func TestConnectProxyRejectsPrivateDNSResolutionByDefault(t *testing.T) {
	proxy, err := NewConnectProxy(ConnectProxyConfig{
		AllowedHost:           "opencode.ai",
		AllowedPort:           443,
		MaxConcurrentRequests: 2,
	}, staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}, func(
		_ context.Context,
		_, _ string,
	) (net.Conn, error) {
		t.Fatal("dial should not occur for private DNS result")
		return nil, errors.New("unreachable")
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://opencode.ai:443", nil)
	req.Host = "opencode.ai:443"
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("private DNS status = %d, want 502", rec.Code)
	}
}

func TestConnectProxyDialsVerifiedIPWithoutSecondDNSLookup(t *testing.T) {
	clientSide, proxyClientSide := net.Pipe()
	upstreamProxySide, upstreamSide := net.Pipe()
	defer clientSide.Close()
	defer upstreamSide.Close()

	var dialAddress atomic.Value
	proxy, err := NewConnectProxy(ConnectProxyConfig{
		AllowedHost:           "opencode.ai",
		AllowedPort:           443,
		MaxConcurrentRequests: 2,
		AllowPrivateUpstream:  true,
		TunnelLifetime:        2 * time.Second,
	}, staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}}, func(
		_ context.Context,
		network, address string,
	) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("dial network = %q", network)
		}
		dialAddress.Store(address)
		return upstreamProxySide, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(proxy.Handler())
	server.Listener = &singleConnListener{conn: proxyClientSide}
	server.Start()
	defer server.Close()

	go func() {
		reader := bufio.NewReader(upstreamSide)
		line, _ := reader.ReadString('\n')
		if line != "hello-through-tunnel\n" {
			return
		}
		_, _ = io.WriteString(upstreamSide, "reply-from-upstream\n")
	}()

	if _, err := io.WriteString(clientSide, "CONNECT opencode.ai:443 HTTP/1.1\r\nHost: opencode.ai:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(clientSide)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("unexpected CONNECT response: %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := io.WriteString(clientSide, "hello-through-tunnel\n"); err != nil {
		t.Fatal(err)
	}
	reply, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if reply != "reply-from-upstream\n" {
		t.Fatalf("unexpected tunnel reply: %q", reply)
	}
	if got, _ := dialAddress.Load().(string); got != "203.0.113.10:443" {
		t.Fatalf("dial address = %q, want verified IP", got)
	}
}

func TestConnectProxyHealth(t *testing.T) {
	proxy, err := NewConnectProxy(ConnectProxyConfig{
		AllowedHost:           "opencode.ai",
		AllowedPort:           443,
		MaxConcurrentRequests: 1,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://awf-egress/healthz", nil)
	proxy.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
}

type singleConnListener struct {
	conn net.Conn
	used atomic.Bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.used.Swap(true) {
		return nil, errors.New("listener closed")
	}
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return dummyAddr("pipe")
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

func TestConnectProxyForwardsBytesBufferedAfterConnectHeaders(t *testing.T) {
	clientSide, proxyClientSide := net.Pipe()
	upstreamProxySide, upstreamSide := net.Pipe()
	defer clientSide.Close()
	defer upstreamSide.Close()

	proxy, err := NewConnectProxy(ConnectProxyConfig{
		AllowedHost:           "opencode.ai",
		AllowedPort:           443,
		MaxConcurrentRequests: 1,
		AllowPrivateUpstream:  true,
		TunnelLifetime:        2 * time.Second,
	}, staticResolver{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}}, func(
		_ context.Context,
		_, _ string,
	) (net.Conn, error) {
		return upstreamProxySide, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(proxy.Handler())
	server.Listener = &singleConnListener{conn: proxyClientSide}
	server.Start()
	defer server.Close()

	upstreamReceived := make(chan string, 1)
	go func() {
		buffer := make([]byte, len("early-tls-bytes"))
		_, _ = io.ReadFull(upstreamSide, buffer)
		upstreamReceived <- string(buffer)
		_, _ = io.WriteString(upstreamSide, "server-reply")
	}()

	// Deliberately pipeline tunnel payload with the CONNECT request so net/http
	// can buffer post-header bytes before Hijack.
	if _, err := io.WriteString(
		clientSide,
		"CONNECT opencode.ai:443 HTTP/1.1\r\nHost: opencode.ai:443\r\n\r\nearly-tls-bytes",
	); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(clientSide)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("unexpected CONNECT response: %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	select {
	case got := <-upstreamReceived:
		if got != "early-tls-bytes" {
			t.Fatalf("upstream received %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipelined bytes were not forwarded")
	}

	reply := make([]byte, len("server-reply"))
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "server-reply" {
		t.Fatalf("unexpected reply %q", string(reply))
	}
}
