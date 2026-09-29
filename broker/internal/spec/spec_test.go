package spec

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

const runsRoot = "/var/lib/autonomous-worker/runs"

func validRequest(now time.Time) Request {
	var req Request
	req.SchemaVersion = "1.0"
	req.RequestID = "req-001"
	req.TaskID = "task-001"
	req.AttemptID = "attempt-001"
	req.MachineID = "production-vps"
	req.Tier = "T1"
	req.RunRoot = runsRoot + "/attempt-001"
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
	req.ExpiresAt = now.Add(5 * time.Minute).Format(time.RFC3339)
	req.WorkspaceLeaseID = "lease-001"
	req.WorkspaceLeaseHash = strings.Repeat("d", 64)
	return req
}

func TestBuildDockerSpecHardensContainer(t *testing.T) {
	now := time.Unix(1_790_000_000, 0).UTC()
	req := validRequest(now)
	spec, err := BuildDockerSpec(req, runsRoot, now, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(spec.CreateArgs, " ")
	for _, required := range []string{
		"--network none",
		"--read-only",
		"--cap-drop ALL",
		"--security-opt no-new-privileges:true",
		"--user 65532:1000",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing hardening arg %q in %s", required, joined)
		}
	}
	if strings.Contains(joined, "/var/run/docker.sock") {
		t.Fatal("docker socket must never be mounted")
	}
}

func TestRejectsEscapedWorkspace(t *testing.T) {
	now := time.Unix(1_790_000_000, 0).UTC()
	req := validRequest(now)
	req.Workspace.Source = "/etc"
	if _, err := BuildDockerSpec(req, runsRoot, now, DefaultLimits()); err == nil {
		t.Fatal("expected escaped workspace to be rejected")
	}
}

func TestRejectsGenericEntrypoint(t *testing.T) {
	now := time.Unix(1_790_000_000, 0).UTC()
	req := validRequest(now)
	req.Command.Argv = []string{"sh", "-c", "id"}
	if _, err := BuildDockerSpec(req, runsRoot, now, DefaultLimits()); err == nil {
		t.Fatal("expected non-opencode entrypoint to be rejected")
	}
}

func TestRejectsLongLivedRequest(t *testing.T) {
	now := time.Unix(1_790_000_000, 0).UTC()
	req := validRequest(now)
	req.ExpiresAt = now.Add(30 * time.Minute).Format(time.RFC3339)
	if err := ValidateRequest(req, runsRoot, now, DefaultLimits()); err == nil {
		t.Fatal("expected expiry outside broker window to be rejected")
	}
}

func TestBindingHashMatchesSharedCrossLanguageVector(t *testing.T) {
	data, err := os.ReadFile("../../../examples/sandbox-request-binding.vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Request      Request `json:"request"`
		ExpectedHash string  `json:"expected_hash"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if got := BindingHash(vector.Request); got != vector.ExpectedHash {
		t.Fatalf("binding hash mismatch: got %s want %s", got, vector.ExpectedHash)
	}
}
