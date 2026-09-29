package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"autonomous-worker/broker/internal/spec"
)

var ErrUnavailable = errors.New("broker backend unavailable")

type PeerCredential struct {
	PID int32
	UID uint32
	GID uint32
}

type peerCredentialKey struct{}

type Runtime interface {
	Ready() bool
	Provision(context.Context, spec.Request) (json.RawMessage, error)
	Status(context.Context, AttemptStatusRequest) (json.RawMessage, error)
	Terminate(context.Context, TerminateRequest) (json.RawMessage, error)
}

type WorkspaceManager interface {
	Ready() bool
	Issue(context.Context, WorkspaceLeaseRequest, uint32, uint32) (json.RawMessage, error)
	Verify(context.Context, spec.Request, uint32, uint32) error
	Release(context.Context, WorkspaceLeaseReleaseRequest, uint32, uint32) (json.RawMessage, error)
}

type Config struct {
	ControllerUID uint32
	MachineID     string
	RunsRoot      string
	BrokerBuild   string
	RequireRoot   bool
	MaxBodyBytes  int64
	Clock         func() time.Time
}

type Server struct {
	cfg        Config
	runtime    Runtime
	workspaces WorkspaceManager
	handler    http.Handler
}

type WorkspaceLeaseRequest struct {
	AttemptID  string `json:"attempt_id"`
	MachineID  string `json:"machine_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type WorkspaceLeaseReleaseRequest struct {
	AttemptID string `json:"attempt_id"`
	MachineID string `json:"machine_id"`
	LeaseID   string `json:"lease_id"`
	LeaseHash string `json:"lease_hash"`
}

type AttemptStatusRequest struct {
	RequestID string `json:"request_id"`
	AttemptID string `json:"attempt_id"`
}

type TerminateRequest struct {
	RequestID string `json:"request_id"`
	AttemptID string `json:"attempt_id"`
}

type healthResponse struct {
	Status                string `json:"status"`
	BrokerBuild           string `json:"broker_build"`
	MachineID             string `json:"machine_id"`
	ControllerUID         uint32 `json:"controller_uid"`
	RuntimeReady          bool   `json:"runtime_ready"`
	WorkspaceManagerReady bool   `json:"workspace_manager_ready"`
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type UnavailableRuntime struct{}

func (UnavailableRuntime) Ready() bool { return false }

func (UnavailableRuntime) Provision(context.Context, spec.Request) (json.RawMessage, error) {
	return nil, ErrUnavailable
}

func (UnavailableRuntime) Status(context.Context, AttemptStatusRequest) (json.RawMessage, error) {
	return nil, ErrUnavailable
}

func (UnavailableRuntime) Terminate(context.Context, TerminateRequest) (json.RawMessage, error) {
	return nil, ErrUnavailable
}

type UnavailableWorkspaceManager struct{}

func (UnavailableWorkspaceManager) Ready() bool { return false }

func (UnavailableWorkspaceManager) Issue(context.Context, WorkspaceLeaseRequest, uint32, uint32) (json.RawMessage, error) {
	return nil, ErrUnavailable
}

func (UnavailableWorkspaceManager) Verify(context.Context, spec.Request, uint32, uint32) error {
	return ErrUnavailable
}

func (UnavailableWorkspaceManager) Release(context.Context, WorkspaceLeaseReleaseRequest, uint32, uint32) (json.RawMessage, error) {
	return nil, ErrUnavailable
}

func New(cfg Config, runtime Runtime, workspaces WorkspaceManager) (*Server, error) {
	if cfg.ControllerUID == 0 {
		return nil, errors.New("controller UID must be non-root and explicit")
	}
	if cfg.MachineID == "" {
		return nil, errors.New("machine ID is required")
	}
	if cfg.RunsRoot == "" || !filepath.IsAbs(cfg.RunsRoot) {
		return nil, errors.New("runs root must be an absolute path")
	}
	if cfg.BrokerBuild == "" {
		return nil, errors.New("broker build is required")
	}
	if cfg.RequireRoot && os.Geteuid() != 0 {
		return nil, errors.New("production broker server requires root")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if runtime == nil {
		runtime = UnavailableRuntime{}
	}
	if workspaces == nil {
		workspaces = UnavailableWorkspaceManager{}
	}

	s := &Server{cfg: cfg, runtime: runtime, workspaces: workspaces}
	s.handler = s.authenticated(s.routes())
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/workspace-leases", s.handleWorkspaceLease)
	mux.HandleFunc("POST /v1/workspace-leases/release", s.handleWorkspaceLeaseRelease)
	mux.HandleFunc("POST /v1/provision", s.handleProvision)
	mux.HandleFunc("POST /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/terminate", s.handleTerminate)
	return mux
}

func (s *Server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := PeerCredentialFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusForbidden, "PEER_CREDENTIAL_MISSING", "Unix peer credentials are required")
			return
		}
		if peer.UID != s.cfg.ControllerUID {
			writeError(w, http.StatusForbidden, "PEER_UID_FORBIDDEN", "peer UID is not authorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	status := "ready"
	if !s.runtime.Ready() || !s.workspaces.Ready() {
		status = "not_ready"
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:                status,
		BrokerBuild:           s.cfg.BrokerBuild,
		MachineID:             s.cfg.MachineID,
		ControllerUID:         s.cfg.ControllerUID,
		RuntimeReady:          s.runtime.Ready(),
		WorkspaceManagerReady: s.workspaces.Ready(),
	})
}

func (s *Server) handleWorkspaceLease(w http.ResponseWriter, r *http.Request) {
	var req WorkspaceLeaseRequest
	if err := s.decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.AttemptID == "" || req.MachineID == "" || req.TTLSeconds < 1 || req.TTLSeconds > 3600 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid workspace lease request")
		return
	}
	peer, _ := PeerCredentialFromContext(r.Context())
	payload, err := s.workspaces.Issue(r.Context(), req, peer.UID, peer.GID)
	if err != nil {
		s.writeBackendError(w, err)
		return
	}
	writeRawJSON(w, http.StatusCreated, payload)
}

func (s *Server) handleWorkspaceLeaseRelease(w http.ResponseWriter, r *http.Request) {
	var req WorkspaceLeaseReleaseRequest
	if err := s.decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.AttemptID == "" || req.MachineID == "" || req.LeaseID == "" ||
		!regexp.MustCompile("^[0-9a-f]{64}$").MatchString(req.LeaseHash) {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid workspace lease release request")
		return
	}
	peer, _ := PeerCredentialFromContext(r.Context())
	payload, err := s.workspaces.Release(r.Context(), req, peer.UID, peer.GID)
	if err != nil {
		s.writeBackendError(w, err)
		return
	}
	writeRawJSON(w, http.StatusOK, payload)
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	var req spec.Request
	if err := s.decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if err := spec.ValidateRequest(req, s.cfg.RunsRoot, s.cfg.Clock(), spec.DefaultLimits()); err != nil {
		writeError(w, http.StatusBadRequest, "POLICY_REJECTED", err.Error())
		return
	}
	peer, _ := PeerCredentialFromContext(r.Context())
	if err := s.workspaces.Verify(r.Context(), req, peer.UID, peer.GID); err != nil {
		if errors.Is(err, ErrUnavailable) {
			s.writeBackendError(w, err)
		} else {
			writeError(w, http.StatusBadRequest, "WORKSPACE_LEASE_REJECTED", err.Error())
		}
		return
	}
	payload, err := s.runtime.Provision(r.Context(), req)
	if err != nil {
		s.writeBackendError(w, err)
		return
	}
	writeRawJSON(w, http.StatusCreated, payload)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var req AttemptStatusRequest
	if err := s.decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.RequestID == "" || req.AttemptID == "" ||
		len(req.RequestID) > 128 || len(req.AttemptID) > 128 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request_id and attempt_id are required")
		return
	}
	payload, err := s.runtime.Status(r.Context(), req)
	if err != nil {
		s.writeBackendError(w, err)
		return
	}
	writeRawJSON(w, http.StatusOK, payload)
}

func (s *Server) handleTerminate(w http.ResponseWriter, r *http.Request) {
	var req TerminateRequest
	if err := s.decodeStrictJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if req.RequestID == "" || req.AttemptID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request_id and attempt_id are required")
		return
	}
	payload, err := s.runtime.Terminate(r.Context(), req)
	if err != nil {
		s.writeBackendError(w, err)
		return
	}
	writeRawJSON(w, http.StatusOK, payload)
}

func (s *Server) decodeStrictJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" && !strings.HasPrefix(contentType, "application/json;") {
		return errors.New("Content-Type must be application/json")
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func (s *Server) writeBackendError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "broker backend is not ready")
		return
	}
	writeError(w, http.StatusInternalServerError, "BROKER_INTERNAL_ERROR", "broker backend failed")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeRawJSON(w http.ResponseWriter, status int, payload json.RawMessage) {
	if !json.Valid(payload) {
		writeError(w, http.StatusInternalServerError, "BROKER_INVALID_RESPONSE", "backend returned invalid JSON")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(payload, '\n'))
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var envelope errorEnvelope
	envelope.Error.Code = code
	envelope.Error.Message = message
	writeJSON(w, status, envelope)
}

func ContextWithPeerCredential(ctx context.Context, peer PeerCredential) context.Context {
	return context.WithValue(ctx, peerCredentialKey{}, peer)
}

func PeerCredentialFromContext(ctx context.Context) (PeerCredential, bool) {
	peer, ok := ctx.Value(peerCredentialKey{}).(PeerCredential)
	return peer, ok
}

func UnixConnContext(ctx context.Context, conn net.Conn) context.Context {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return ctx
	}

	var (
		cred    *syscall.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return ctx
	}

	return ContextWithPeerCredential(ctx, PeerCredential{
		PID: cred.Pid,
		UID: cred.Uid,
		GID: cred.Gid,
	})
}

func (s *Server) ListenAndServeUnix(ctx context.Context, socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return errors.New("socket path must be absolute")
	}
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0o755); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	dirInfo, err := os.Lstat(socketDir)
	if err != nil {
		return fmt.Errorf("stat socket directory: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("socket parent must be a real directory")
	}
	resolvedSocketDir, err := filepath.EvalSymlinks(socketDir)
	if err != nil {
		return fmt.Errorf("resolve socket parent: %w", err)
	}
	if filepath.Clean(resolvedSocketDir) != filepath.Clean(socketDir) {
		return errors.New("socket parent must not traverse symlinks")
	}
	if dirInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("socket parent must not be group/world writable")
	}
	if s.cfg.RequireRoot {
		stat, ok := dirInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("production socket parent must be root-owned")
		}
	}

	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace non-socket path")
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat socket path: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	if err := os.Chown(socketPath, int(s.cfg.ControllerUID), -1); err != nil {
		return fmt.Errorf("chown socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	httpServer := &http.Server{
		Handler:      s.Handler(),
		ConnContext:  UnixConnContext,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func ParseControllerUID(value string) (uint32, error) {
	uid64, err := strconv.ParseUint(value, 10, 32)
	if err != nil || uid64 == 0 {
		return 0, errors.New("controller UID must be a positive numeric UID")
	}
	return uint32(uid64), nil
}
