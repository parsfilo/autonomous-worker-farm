package workspace

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"autonomous-worker/broker/internal/server"
	"autonomous-worker/broker/internal/spec"
)

var (
	idPattern   = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
	hashPattern = regexp.MustCompile("^[0-9a-f]{64}$")
)

type Config struct {
	RunsRoot    string
	BrokerBuild string
	RequireRoot bool
	Clock       func() time.Time
}

type Manager struct {
	cfg Config
	mu  sync.Mutex
}

type Lease struct {
	SchemaVersion   string     `json:"schema_version"`
	LeaseID         string     `json:"lease_id"`
	AttemptID       string     `json:"attempt_id"`
	MachineID       string     `json:"machine_id"`
	ControllerUID   uint32     `json:"controller_uid"`
	ControllerGID   uint32     `json:"controller_gid"`
	Paths           LeasePaths `json:"paths"`
	CreatedAt       string     `json:"created_at"`
	ExpiresAt       string     `json:"expires_at"`
	BrokerBuild     string     `json:"broker_build"`
	ImmutableParent bool       `json:"immutable_parent"`
	LeaseHash       string     `json:"lease_hash"`
}

type LeasePaths struct {
	RunRoot   string `json:"run_root"`
	Repo      string `json:"repo"`
	Control   string `json:"control"`
	Artifacts string `json:"artifacts"`
}

type persistedLease struct {
	SchemaVersion   string     `json:"schema_version"`
	LeaseID         string     `json:"lease_id"`
	AttemptID       string     `json:"attempt_id"`
	MachineID       string     `json:"machine_id"`
	ControllerUID   uint32     `json:"controller_uid"`
	ControllerGID   uint32     `json:"controller_gid"`
	Paths           LeasePaths `json:"paths"`
	CreatedAt       string     `json:"created_at"`
	ExpiresAt       string     `json:"expires_at"`
	BrokerBuild     string     `json:"broker_build"`
	ImmutableParent bool       `json:"immutable_parent"`
	LeaseHash       string     `json:"lease_hash"`
}

type unsignedLease struct {
	SchemaVersion   string     `json:"schema_version"`
	LeaseID         string     `json:"lease_id"`
	AttemptID       string     `json:"attempt_id"`
	MachineID       string     `json:"machine_id"`
	ControllerUID   uint32     `json:"controller_uid"`
	ControllerGID   uint32     `json:"controller_gid"`
	Paths           LeasePaths `json:"paths"`
	CreatedAt       string     `json:"created_at"`
	ExpiresAt       string     `json:"expires_at"`
	BrokerBuild     string     `json:"broker_build"`
	ImmutableParent bool       `json:"immutable_parent"`
}

func New(cfg Config) (*Manager, error) {
	if cfg.RunsRoot == "" || !filepath.IsAbs(cfg.RunsRoot) {
		return nil, errors.New("runs root must be absolute")
	}
	if cfg.BrokerBuild == "" {
		return nil, errors.New("broker build is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.RequireRoot && os.Geteuid() != 0 {
		return nil, errors.New("production workspace manager requires root")
	}
	return &Manager{cfg: cfg}, nil
}

func (m *Manager) Ready() bool {
	return !m.cfg.RequireRoot || os.Geteuid() == 0
}

func (m *Manager) Issue(
	ctx context.Context,
	req server.WorkspaceLeaseRequest,
	controllerUID uint32,
	controllerGID uint32,
) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if controllerUID == 0 {
		return nil, errors.New("root controller UID is forbidden")
	}
	if !idPattern.MatchString(req.AttemptID) || !idPattern.MatchString(req.MachineID) {
		return nil, errors.New("invalid attempt_id or machine_id")
	}
	if req.TTLSeconds < 1 || req.TTLSeconds > 3600 {
		return nil, errors.New("ttl_seconds outside accepted range")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureRunsRoot(); err != nil {
		return nil, err
	}

	runRoot := filepath.Join(filepath.Clean(m.cfg.RunsRoot), req.AttemptID)
	if _, err := os.Lstat(runRoot); err == nil {
		return nil, errors.New("attempt workspace already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat attempt workspace: %w", err)
	}

	if err := os.Mkdir(runRoot, 0o711); err != nil {
		return nil, fmt.Errorf("create attempt workspace: %w", err)
	}
	// The production systemd unit intentionally uses UMask=0077. Mkdir's mode
	// is therefore masked to 0700 unless we restore the broker invariant
	// explicitly. The root-owned parent must be traversable (not listable or
	// writable) by the authorized Controller so it can reach leased children.
	if err := os.Chmod(runRoot, 0o711); err != nil {
		return nil, fmt.Errorf("chmod attempt workspace: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = os.RemoveAll(runRoot)
		}
	}()

	paths := LeasePaths{
		RunRoot:   runRoot,
		Repo:      filepath.Join(runRoot, "repo"),
		Control:   filepath.Join(runRoot, "control"),
		Artifacts: filepath.Join(runRoot, "artifacts"),
	}
	for _, path := range []string{paths.Repo, paths.Control, paths.Artifacts} {
		if err := os.Mkdir(path, 0o770); err != nil {
			return nil, fmt.Errorf("create lease child: %w", err)
		}
		if err := os.Chown(path, int(controllerUID), int(controllerGID)); err != nil {
			return nil, fmt.Errorf("chown lease child: %w", err)
		}
		mode := os.FileMode(0o770)
		if m.cfg.RequireRoot {
			mode |= os.ModeSetgid
		}
		if err := os.Chmod(path, mode); err != nil {
			return nil, fmt.Errorf("chmod lease child: %w", err)
		}
	}

	now := m.cfg.Clock().UTC()
	leaseID, err := newLeaseID()
	if err != nil {
		return nil, err
	}
	unsigned := unsignedLease{
		SchemaVersion:   "1.0",
		LeaseID:         leaseID,
		AttemptID:       req.AttemptID,
		MachineID:       req.MachineID,
		ControllerUID:   controllerUID,
		ControllerGID:   controllerGID,
		Paths:           paths,
		CreatedAt:       now.Format(time.RFC3339),
		ExpiresAt:       now.Add(time.Duration(req.TTLSeconds) * time.Second).Format(time.RFC3339),
		BrokerBuild:     m.cfg.BrokerBuild,
		ImmutableParent: true,
	}
	leaseHash, err := hashUnsigned(unsigned)
	if err != nil {
		return nil, err
	}
	stored := persistedLease{
		SchemaVersion:   unsigned.SchemaVersion,
		LeaseID:         unsigned.LeaseID,
		AttemptID:       unsigned.AttemptID,
		MachineID:       unsigned.MachineID,
		ControllerUID:   unsigned.ControllerUID,
		ControllerGID:   unsigned.ControllerGID,
		Paths:           unsigned.Paths,
		CreatedAt:       unsigned.CreatedAt,
		ExpiresAt:       unsigned.ExpiresAt,
		BrokerBuild:     unsigned.BrokerBuild,
		ImmutableParent: unsigned.ImmutableParent,
		LeaseHash:       leaseHash,
	}
	metadata, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal persisted lease: %w", err)
	}
	metadata = append(metadata, '\n')
	if err := os.WriteFile(filepath.Join(runRoot, ".lease.json"), metadata, 0o600); err != nil {
		return nil, fmt.Errorf("write lease metadata: %w", err)
	}

	response := Lease{
		SchemaVersion:   stored.SchemaVersion,
		LeaseID:         stored.LeaseID,
		AttemptID:       stored.AttemptID,
		MachineID:       stored.MachineID,
		ControllerUID:   stored.ControllerUID,
		ControllerGID:   stored.ControllerGID,
		Paths:           stored.Paths,
		CreatedAt:       stored.CreatedAt,
		ExpiresAt:       stored.ExpiresAt,
		BrokerBuild:     stored.BrokerBuild,
		ImmutableParent: stored.ImmutableParent,
		LeaseHash:       stored.LeaseHash,
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("marshal lease response: %w", err)
	}

	rollback = false
	return payload, nil
}

func (m *Manager) Verify(
	ctx context.Context,
	req spec.Request,
	controllerUID uint32,
	controllerGID uint32,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if controllerUID == 0 {
		return errors.New("root controller UID is forbidden")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	runRoot := filepath.Join(filepath.Clean(m.cfg.RunsRoot), req.AttemptID)
	if filepath.Clean(req.RunRoot) != runRoot {
		return errors.New("request run_root differs from broker-derived run root")
	}

	stored, err := m.loadLease(runRoot)
	if err != nil {
		return err
	}
	if stored.LeaseID != req.WorkspaceLeaseID || stored.LeaseHash != req.WorkspaceLeaseHash {
		return errors.New("workspace lease identity/hash mismatch")
	}
	if stored.AttemptID != req.AttemptID || stored.MachineID != req.MachineID {
		return errors.New("workspace lease attempt/machine mismatch")
	}
	if stored.ControllerUID != controllerUID || stored.ControllerGID != controllerGID {
		return errors.New("workspace lease peer identity mismatch")
	}
	if req.Workspace.ControllerGID != stored.ControllerGID {
		return errors.New("request workspace controller_gid differs from lease")
	}
	if stored.BrokerBuild != m.cfg.BrokerBuild || !stored.ImmutableParent {
		return errors.New("workspace lease broker binding mismatch")
	}

	expiresAt, err := time.Parse(time.RFC3339, stored.ExpiresAt)
	if err != nil || !expiresAt.After(m.cfg.Clock()) {
		return errors.New("workspace lease expired")
	}

	unsigned := unsignedLease{
		SchemaVersion:   stored.SchemaVersion,
		LeaseID:         stored.LeaseID,
		AttemptID:       stored.AttemptID,
		MachineID:       stored.MachineID,
		ControllerUID:   stored.ControllerUID,
		ControllerGID:   stored.ControllerGID,
		Paths:           stored.Paths,
		CreatedAt:       stored.CreatedAt,
		ExpiresAt:       stored.ExpiresAt,
		BrokerBuild:     stored.BrokerBuild,
		ImmutableParent: stored.ImmutableParent,
	}
	expectedHash, err := hashUnsigned(unsigned)
	if err != nil {
		return err
	}
	if expectedHash != stored.LeaseHash {
		return errors.New("persisted workspace lease hash mismatch")
	}

	if stored.Paths.RunRoot != runRoot ||
		stored.Paths.Repo != filepath.Join(runRoot, "repo") ||
		stored.Paths.Control != filepath.Join(runRoot, "control") ||
		stored.Paths.Artifacts != filepath.Join(runRoot, "artifacts") {
		return errors.New("persisted workspace lease paths are invalid")
	}
	if filepath.Clean(req.Workspace.Source) != stored.Paths.Repo {
		return errors.New("request workspace source differs from leased repo path")
	}

	if err := m.verifyFilesystem(stored, controllerUID, controllerGID); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Release(
	ctx context.Context,
	req server.WorkspaceLeaseReleaseRequest,
	controllerUID uint32,
	controllerGID uint32,
) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if controllerUID == 0 {
		return nil, errors.New("root controller UID is forbidden")
	}
	if !idPattern.MatchString(req.AttemptID) ||
		!idPattern.MatchString(req.MachineID) ||
		!idPattern.MatchString(req.LeaseID) ||
		!hashPattern.MatchString(req.LeaseHash) {
		return nil, errors.New("invalid workspace lease release identity")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureRunsRoot(); err != nil {
		return nil, err
	}
	runsRoot := filepath.Clean(m.cfg.RunsRoot)
	runRoot := filepath.Join(runsRoot, req.AttemptID)
	if filepath.Dir(runRoot) != runsRoot || runRoot == runsRoot {
		return nil, errors.New("workspace release path escaped runs root")
	}

	stored, err := m.loadLease(runRoot)
	if err != nil {
		return nil, err
	}
	if stored.AttemptID != req.AttemptID ||
		stored.MachineID != req.MachineID ||
		stored.LeaseID != req.LeaseID ||
		stored.LeaseHash != req.LeaseHash {
		return nil, errors.New("workspace lease release binding mismatch")
	}
	if stored.ControllerUID != controllerUID || stored.ControllerGID != controllerGID {
		return nil, errors.New("workspace lease release peer identity mismatch")
	}
	if stored.BrokerBuild != m.cfg.BrokerBuild || !stored.ImmutableParent {
		return nil, errors.New("workspace lease release broker binding mismatch")
	}

	unsigned := unsignedLease{
		SchemaVersion:   stored.SchemaVersion,
		LeaseID:         stored.LeaseID,
		AttemptID:       stored.AttemptID,
		MachineID:       stored.MachineID,
		ControllerUID:   stored.ControllerUID,
		ControllerGID:   stored.ControllerGID,
		Paths:           stored.Paths,
		CreatedAt:       stored.CreatedAt,
		ExpiresAt:       stored.ExpiresAt,
		BrokerBuild:     stored.BrokerBuild,
		ImmutableParent: stored.ImmutableParent,
	}
	expectedHash, err := hashUnsigned(unsigned)
	if err != nil {
		return nil, err
	}
	if expectedHash != stored.LeaseHash {
		return nil, errors.New("persisted workspace lease hash mismatch")
	}

	if stored.Paths.RunRoot != runRoot ||
		stored.Paths.Repo != filepath.Join(runRoot, "repo") ||
		stored.Paths.Control != filepath.Join(runRoot, "control") ||
		stored.Paths.Artifacts != filepath.Join(runRoot, "artifacts") {
		return nil, errors.New("persisted workspace release paths are invalid")
	}
	if err := m.verifyFilesystem(stored, controllerUID, controllerGID); err != nil {
		return nil, err
	}

	if err := os.RemoveAll(runRoot); err != nil {
		return nil, fmt.Errorf("remove workspace lease: %w", err)
	}
	if _, err := os.Lstat(runRoot); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return nil, errors.New("workspace lease survived release")
		}
		return nil, fmt.Errorf("verify workspace lease release: %w", err)
	}

	return json.Marshal(map[string]any{
		"status":     "RELEASED",
		"attempt_id": req.AttemptID,
		"machine_id": req.MachineID,
		"lease_id":   req.LeaseID,
		"removed":    true,
	})
}

func (m *Manager) ensureRunsRoot() error {
	if err := os.MkdirAll(m.cfg.RunsRoot, 0o755); err != nil {
		return fmt.Errorf("create runs root: %w", err)
	}
	info, err := os.Lstat(m.cfg.RunsRoot)
	if err != nil {
		return fmt.Errorf("stat runs root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("runs root must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(m.cfg.RunsRoot)
	if err != nil {
		return fmt.Errorf("resolve runs root: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(m.cfg.RunsRoot) {
		return errors.New("runs root must not traverse symlinks")
	}
	if m.cfg.RequireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("production runs root must be root-owned")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return errors.New("production runs root must not be group/world writable")
		}
	}
	return nil
}

func (m *Manager) loadLease(runRoot string) (persistedLease, error) {
	path := filepath.Join(runRoot, ".lease.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedLease{}, fmt.Errorf("read lease metadata: %w", err)
	}
	var lease persistedLease
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lease); err != nil {
		return persistedLease{}, fmt.Errorf("decode lease metadata: %w", err)
	}
	return lease, nil
}

func (m *Manager) verifyFilesystem(lease persistedLease, uid, gid uint32) error {
	runInfo, err := os.Lstat(lease.Paths.RunRoot)
	if err != nil {
		return fmt.Errorf("stat run root: %w", err)
	}
	if !runInfo.IsDir() || runInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("run root is not a real directory")
	}
	if runInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("run root is writable by group/other")
	}
	if m.cfg.RequireRoot {
		stat, ok := runInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("production run root is not root-owned")
		}
	}

	for _, path := range []string{lease.Paths.Repo, lease.Paths.Control, lease.Paths.Artifacts} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("stat lease child: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("lease child is not a real directory")
		}
		if info.Mode().Perm() != 0o770 {
			return errors.New("lease child permissions changed")
		}
		if m.cfg.RequireRoot && info.Mode()&os.ModeSetgid == 0 {
			return errors.New("production lease child lost setgid bit")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uid || stat.Gid != gid {
			return errors.New("lease child ownership changed")
		}
	}

	metaInfo, err := os.Lstat(filepath.Join(lease.Paths.RunRoot, ".lease.json"))
	if err != nil {
		return fmt.Errorf("stat lease metadata: %w", err)
	}
	if !metaInfo.Mode().IsRegular() || metaInfo.Mode().Perm() != 0o600 {
		return errors.New("lease metadata permissions changed")
	}
	if m.cfg.RequireRoot {
		stat, ok := metaInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("production lease metadata is not root-owned")
		}
	}
	return nil
}

func newLeaseID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate lease id: %w", err)
	}
	return "lease-" + hex.EncodeToString(raw[:]), nil
}

func hashUnsigned(value unsignedLease) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal lease hash input: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
