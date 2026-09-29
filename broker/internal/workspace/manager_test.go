package workspace

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"autonomous-worker/broker/internal/server"
	"autonomous-worker/broker/internal/spec"
)

func testManager(t *testing.T, now *time.Time) *Manager {
	t.Helper()
	m, err := New(Config{
		RunsRoot:    t.TempDir() + "/runs",
		BrokerBuild: "test-build",
		RequireRoot: false,
		Clock: func() time.Time {
			return *now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func issueLease(t *testing.T, m *Manager, uid, gid uint32) Lease {
	t.Helper()
	payload, err := m.Issue(
		context.Background(),
		server.WorkspaceLeaseRequest{
			AttemptID:  "attempt-001",
			MachineID:  "production-vps",
			TTLSeconds: 300,
		},
		uid,
		gid,
	)
	if err != nil {
		t.Fatal(err)
	}
	var lease Lease
	if err := json.Unmarshal(payload, &lease); err != nil {
		t.Fatal(err)
	}
	return lease
}

func requestForLease(lease Lease) spec.Request {
	var req spec.Request
	req.SchemaVersion = "1.0"
	req.RequestID = "req-001"
	req.TaskID = "task-001"
	req.AttemptID = lease.AttemptID
	req.MachineID = lease.MachineID
	req.Tier = "T1"
	req.RunRoot = lease.Paths.RunRoot
	req.Workspace.Source = lease.Paths.Repo
	req.Workspace.MountPath = "/workspace"
	req.Workspace.BaseSHA = "0123456789abcdef0123456789abcdef01234567"
	req.Workspace.ControllerGID = lease.ControllerGID
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
	req.ExpiresAt = lease.ExpiresAt
	req.WorkspaceLeaseID = lease.LeaseID
	req.WorkspaceLeaseHash = lease.LeaseHash
	return req
}

func TestIssueAndVerifyPersistentLease(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	if !lease.ImmutableParent {
		t.Fatal("lease must attest immutable parent")
	}
	if len(lease.LeaseHash) != 64 {
		t.Fatalf("unexpected lease hash: %q", lease.LeaseHash)
	}

	req := requestForLease(lease)
	if err := m.Verify(context.Background(), req, uid, gid); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	// New manager instance proves verification does not depend on in-memory lease state.
	restarted, err := New(Config{
		RunsRoot:    m.cfg.RunsRoot,
		BrokerBuild: "test-build",
		RequireRoot: false,
		Clock: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Verify(context.Background(), req, uid, gid); err != nil {
		t.Fatalf("verify after restart failed: %v", err)
	}
}

func TestDuplicateAttemptWorkspaceIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	_ = issueLease(t, m, uid, gid)
	_, err := m.Issue(
		context.Background(),
		server.WorkspaceLeaseRequest{AttemptID: "attempt-001", MachineID: "production-vps", TTLSeconds: 300},
		uid,
		gid,
	)
	if err == nil {
		t.Fatal("expected duplicate attempt workspace to be rejected")
	}
}

func TestLeaseHashSubstitutionIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	req := requestForLease(lease)
	req.WorkspaceLeaseHash = strings.Repeat("f", 64)

	if err := m.Verify(context.Background(), req, uid, gid); err == nil {
		t.Fatal("expected lease hash substitution to be rejected")
	}
}

func TestPeerIdentityMismatchIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	req := requestForLease(lease)

	if err := m.Verify(context.Background(), req, uid+1, gid); err == nil {
		t.Fatal("expected peer UID mismatch to be rejected")
	}
}

func TestPermissionTamperingIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	req := requestForLease(lease)
	if err := os.Chmod(lease.Paths.Repo, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := m.Verify(context.Background(), req, uid, gid); err == nil {
		t.Fatal("expected permission tampering to be rejected")
	}
}

func TestExpiredLeaseIsRejected(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	req := requestForLease(lease)
	now = now.Add(10 * time.Minute)

	if err := m.Verify(context.Background(), req, uid, gid); err == nil {
		t.Fatal("expected expired lease to be rejected")
	}
}

func TestIssueRestoresRunRootTraverseBitsUnderRestrictiveUmask(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)

	lease := issueLease(t, m, uid, gid)
	info, err := os.Stat(lease.Paths.RunRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o711 {
		t.Fatalf("run root mode = %04o, want 0711", got)
	}
}

func TestReleaseRemovesOnlyExactBoundLease(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	payload, err := m.Release(
		context.Background(),
		server.WorkspaceLeaseReleaseRequest{
			AttemptID: lease.AttemptID,
			MachineID: lease.MachineID,
			LeaseID:   lease.LeaseID,
			LeaseHash: lease.LeaseHash,
		},
		uid,
		gid,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "\"status\":\"RELEASED\"") {
		t.Fatalf("unexpected release payload: %s", payload)
	}
	if _, err := os.Lstat(lease.Paths.RunRoot); !os.IsNotExist(err) {
		t.Fatalf("run root survived release: %v", err)
	}
}

func TestReleaseRejectsWrongHashWithoutDeletingWorkspace(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	_, err := m.Release(
		context.Background(),
		server.WorkspaceLeaseReleaseRequest{
			AttemptID: lease.AttemptID,
			MachineID: lease.MachineID,
			LeaseID:   lease.LeaseID,
			LeaseHash: strings.Repeat("f", 64),
		},
		uid,
		gid,
	)
	if err == nil {
		t.Fatal("expected wrong release hash to be rejected")
	}
	if _, err := os.Stat(lease.Paths.RunRoot); err != nil {
		t.Fatalf("workspace was deleted after rejected release: %v", err)
	}
}

func TestReleaseRejectsPeerMismatchWithoutDeletingWorkspace(t *testing.T) {
	now := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	m := testManager(t, &now)
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	if uid == 0 {
		t.Skip("test is intended for non-root controller identity")
	}

	lease := issueLease(t, m, uid, gid)
	_, err := m.Release(
		context.Background(),
		server.WorkspaceLeaseReleaseRequest{
			AttemptID: lease.AttemptID,
			MachineID: lease.MachineID,
			LeaseID:   lease.LeaseID,
			LeaseHash: lease.LeaseHash,
		},
		uid+1,
		gid,
	)
	if err == nil {
		t.Fatal("expected peer mismatch to be rejected")
	}
	if _, err := os.Stat(lease.Paths.RunRoot); err != nil {
		t.Fatalf("workspace was deleted after rejected release: %v", err)
	}
}
