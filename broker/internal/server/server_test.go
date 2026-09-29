package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"autonomous-worker/broker/internal/spec"
)

const testRunsRoot = "/var/lib/autonomous-worker/runs"

func newTestServer(t *testing.T, allowedUID uint32) *Server {
	t.Helper()
	s, err := New(Config{
		ControllerUID: allowedUID,
		MachineID:     "test-machine",
		RunsRoot:      testRunsRoot,
		BrokerBuild:   "test-build",
		MaxBodyBytes:  1 << 20,
		Clock: func() time.Time {
			return time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
		},
	}, UnavailableRuntime{}, UnavailableWorkspaceManager{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func requestWithPeer(method, path string, body io.Reader, uid uint32) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req = req.WithContext(ContextWithPeerCredential(req.Context(), PeerCredential{UID: uid, GID: uid, PID: 123}))
	return req
}

func validProvisionRequest() spec.Request {
	var req spec.Request
	req.SchemaVersion = "1.0"
	req.RequestID = "req-001"
	req.TaskID = "task-001"
	req.AttemptID = "attempt-001"
	req.MachineID = "production-vps"
	req.Tier = "T1"
	req.RunRoot = testRunsRoot + "/attempt-001"
	req.Workspace.Source = req.RunRoot + "/repo"
	req.Workspace.MountPath = "/workspace"
	req.Workspace.BaseSHA = "0123456789abcdef0123456789abcdef01234567"
	req.Workspace.ControllerGID = 1000
	req.Image.Reference = "autonomous-worker-runtime"
	req.Image.Digest = "sha256:" + strings.Repeat("a", 64)
	req.Network.Profile = "none"
	req.Resources.CPU = 1
	req.Resources.MemoryBytes = 1 << 30
	req.Resources.PIDs = 256
	req.Resources.TmpfsBytes = 256 << 20
	req.Resources.TimeoutSeconds = 1800
	req.Command.Argv = []string{"opencode", "run", "--standalone", "--format", "json", "--agent", "build", "--title", "AWF Worker", "--file", "control/task.md", "Execute the task described in the attached task file. Work only in repo/."}
	req.PolicyHash = strings.Repeat("b", 64)
	req.ExpiresAt = "2026-09-28T01:05:00Z"
	req.WorkspaceLeaseID = "lease-001"
	req.WorkspaceLeaseHash = strings.Repeat("d", 64)
	return req
}

func TestRejectsMissingPeerCredential(t *testing.T) {
	s := newTestServer(t, 1000)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRejectsWrongPeerUID(t *testing.T) {
	s := newTestServer(t, 1000)
	rec := httptest.NewRecorder()
	req := requestWithPeer(http.MethodGet, "/v1/health", nil, 1001)
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestHealthIsNotReadyUntilBackendsAreWired(t *testing.T) {
	s := newTestServer(t, 1000)
	rec := httptest.NewRecorder()
	req := requestWithPeer(http.MethodGet, "/v1/health", nil, 1000)
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "\"status\":\"not_ready\"") || !strings.Contains(rec.Body.String(), "\"machine_id\":\"test-machine\"") {
		t.Fatalf("unexpected health body: %s", rec.Body.String())
	}
}

func TestProvisionRejectsUnknownJSONFields(t *testing.T) {
	s := newTestServer(t, 1000)
	payload, err := json.Marshal(validProvisionRequest())
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.TrimSuffix(payload, []byte("}"))
	payload = append(payload, []byte(",\"exec\":\"id\"}")...)

	rec := httptest.NewRecorder()
	req := requestWithPeer(http.MethodPost, "/v1/provision", bytes.NewReader(payload), 1000)
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestProvisionFailsClosedWhenRuntimeUnavailable(t *testing.T) {
	s := newTestServer(t, 1000)
	payload, _ := json.Marshal(validProvisionRequest())

	rec := httptest.NewRecorder()
	req := requestWithPeer(http.MethodPost, "/v1/provision", bytes.NewReader(payload), 1000)
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGenericExecEndpointDoesNotExist(t *testing.T) {
	s := newTestServer(t, 1000)
	rec := httptest.NewRecorder()
	req := requestWithPeer(http.MethodPost, "/v1/exec", strings.NewReader("{\"command\":\"id\"}"), 1000)
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestUnixSocketUsesSO_PEERCRED(t *testing.T) {
	uid := uint32(os.Getuid())
	if uid == 0 {
		t.Skip("test requires a non-root controller UID")
	}
	s := newTestServer(t, uid)
	socket := filepath.Join(t.TempDir(), "broker.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenAndServeUnix(ctx, socket)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unix socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	resp, err := client.Get("http://unix/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 over Unix socket, got %d: %s", resp.StatusCode, string(body))
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestUnixSocketRejectsIntermediateSymlinkParent(t *testing.T) {
	uid := uint32(os.Getuid())
	if uid == 0 {
		uid = 1000
	}
	s := newTestServer(t, uid)
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(link, "child", "broker.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := s.ListenAndServeUnix(ctx, socket)
	if err == nil || !strings.Contains(err.Error(), "must not traverse symlinks") {
		t.Fatalf("expected intermediate symlink parent rejection, got %v", err)
	}
}
