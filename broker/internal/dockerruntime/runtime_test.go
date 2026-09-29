package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"autonomous-worker/broker/internal/server"
	"autonomous-worker/broker/internal/spec"
)

const testRunsRoot = "/var/lib/autonomous-worker/runs"

type fakeCLI struct {
	calls [][]string
	run   func([]string) ([]byte, []byte, error)
}

func (f *fakeCLI) Run(_ context.Context, args ...string) ([]byte, []byte, error) {
	copied := append([]string(nil), args...)
	f.calls = append(f.calls, copied)
	return f.run(copied)
}

func testClock() time.Time {
	return time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
}

func testRequest() spec.Request {
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
	req.Resources.CPU = 1.5
	req.Resources.MemoryBytes = 1 << 30
	req.Resources.PIDs = 256
	req.Resources.TmpfsBytes = 256 << 20
	req.Resources.TimeoutSeconds = 1800
	req.Command.Argv = []string{"opencode", "run", "--standalone", "--format", "json", "--agent", "build", "--title", "AWF Worker", "--file", "control/task.md", "Execute the task described in the attached task file. Work only in repo/."}
	req.PolicyHash = strings.Repeat("b", 64)
	req.ExpiresAt = testClock().Add(5 * time.Minute).Format(time.RFC3339)
	req.WorkspaceLeaseID = "lease-001"
	req.WorkspaceLeaseHash = strings.Repeat("d", 64)
	return req
}

func dockerInfoJSON(seccomp bool) []byte {
	options := []string{"name=apparmor", "name=cgroupns"}
	if seccomp {
		options = append(options, "name=seccomp,profile=builtin")
	}
	payload, _ := json.Marshal(map[string]any{
		"ServerVersion":   "29.8.1",
		"CgroupVersion":   "2",
		"SecurityOptions": options,
	})
	return payload
}

func inspectJSON(t *testing.T, req spec.Request, mutate func(map[string]any)) []byte {
	t.Helper()
	dockerSpec, err := spec.BuildDockerSpec(req, testRunsRoot, testClock(), spec.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("1", 64)

	mounts := make([]map[string]any, 0, len(dockerSpec.Mounts))
	for _, mount := range dockerSpec.Mounts {
		mounts = append(mounts, map[string]any{
			"Type":        "bind",
			"Source":      mount.Source,
			"Destination": mount.Destination,
			"RW":          !mount.ReadOnly,
		})
	}

	value := map[string]any{
		"Id":    id,
		"Image": "sha256:" + strings.Repeat("e", 64),
		"Config": map[string]any{
			"Image": dockerSpec.ExpectedImage,
			"User":  "65532:1000",
			"Labels": map[string]string{
				"awf.request_id":         req.RequestID,
				"awf.task_id":            req.TaskID,
				"awf.attempt_id":         req.AttemptID,
				"awf.workspace_lease_id": req.WorkspaceLeaseID,
			},
			"Env": []string{},
		},
		"HostConfig": map[string]any{
			"NetworkMode":    "none",
			"ReadonlyRootfs": true,
			"Privileged":     false,
			"CapDrop":        []string{"ALL"},
			"SecurityOpt":    []string{"no-new-privileges:true"},
			"PidsLimit":      int64(req.Resources.PIDs),
			"Memory":         req.Resources.MemoryBytes,
			"NanoCpus":       int64(req.Resources.CPU * 1_000_000_000),
			"Tmpfs": map[string]string{
				"/tmp":         "rw,noexec,nosuid,nodev,size=268435456",
				"/home/worker": "rw,nosuid,nodev,size=67108864",
			},
			"Devices":        []any{},
			"DeviceRequests": []any{},
		},
		"Mounts": mounts,
		"State": map[string]any{
			"Running":  false,
			"ExitCode": 0,
		},
	}
	if mutate != nil {
		mutate(value)
	}
	payload, err := json.Marshal([]any{value})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func provisionCLI(t *testing.T, req spec.Request, mutateInspect func(map[string]any)) *fakeCLI {
	t.Helper()
	id := strings.Repeat("1", 64)
	return &fakeCLI{run: func(args []string) ([]byte, []byte, error) {
		if len(args) == 0 {
			return nil, nil, errors.New("empty docker argv")
		}
		switch args[0] {
		case "info":
			return dockerInfoJSON(true), nil, nil
		case "image":
			if len(args) < 3 || args[1] != "inspect" {
				return nil, nil, errors.New("unexpected image command")
			}
			repoDigest := req.Image.Reference + "@" + req.Image.Digest
			payload, _ := json.Marshal([]string{repoDigest})
			return payload, nil, nil
		case "create":
			return []byte(id + "\n"), nil, nil
		case "inspect":
			return inspectJSON(t, req, mutateInspect), nil, nil
		case "start":
			return []byte(id + "\n"), nil, nil
		case "rm":
			return []byte(id + "\n"), nil, nil
		default:
			return nil, nil, errors.New("unexpected docker command: " + strings.Join(args, " "))
		}
	}}
}

func newRuntime(t *testing.T, cli CLI) *Runtime {
	t.Helper()
	runtime, err := New(Config{
		RunsRoot:    testRunsRoot,
		BrokerBuild: "broker-build-001",
		MachineID:   "production-vps",
		RequireRoot: false,
		Clock:       testClock,
	}, cli)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestProvisionUsesPinnedLocalImageAndProducesBoundAttestation(t *testing.T) {
	req := testRequest()
	cli := provisionCLI(t, req, nil)
	runtime := newRuntime(t, cli)

	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	payload, err := runtime.Provision(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	var att map[string]any
	if err := json.Unmarshal(payload, &att); err != nil {
		t.Fatal(err)
	}
	if att["request_hash"] != spec.BindingHash(req) {
		t.Fatalf("unexpected request hash: %v", att["request_hash"])
	}
	if att["image_digest"] != req.Image.Digest {
		t.Fatalf("unexpected image digest: %v", att["image_digest"])
	}

	for _, call := range cli.calls {
		if len(call) > 0 && call[0] == "pull" {
			t.Fatal("broker must never implicitly pull worker images")
		}
		if len(call) > 0 && (call[0] == "run" || call[0] == "exec") {
			t.Fatalf("unexpected generic Docker execution command: %v", call)
		}
	}
}

func TestInspectPolicyDriftDeletesCreatedContainer(t *testing.T) {
	req := testRequest()
	cli := provisionCLI(t, req, func(value map[string]any) {
		host := value["HostConfig"].(map[string]any)
		host["Privileged"] = true
	})
	runtime := newRuntime(t, cli)
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := runtime.Provision(context.Background(), req); err == nil {
		t.Fatal("expected inspect policy drift to fail provisioning")
	}

	foundCleanup := false
	for _, call := range cli.calls {
		if len(call) >= 2 && call[0] == "rm" && call[1] == "-f" {
			foundCleanup = true
		}
	}
	if !foundCleanup {
		t.Fatal("created container was not cleaned up after inspect failure")
	}
}

func TestProbeFailsClosedWithoutSeccomp(t *testing.T) {
	cli := &fakeCLI{run: func(args []string) ([]byte, []byte, error) {
		if len(args) > 0 && args[0] == "info" {
			return dockerInfoJSON(false), nil, nil
		}
		return nil, nil, errors.New("unexpected command")
	}}
	runtime := newRuntime(t, cli)

	if err := runtime.Probe(context.Background()); err == nil {
		t.Fatal("expected probe to reject Docker daemon without seccomp")
	}
	if runtime.Ready() {
		t.Fatal("runtime must remain not ready after failed probe")
	}
}

func TestTerminateResolvesContainerByIdentityLabels(t *testing.T) {
	req := testRequest()
	id := strings.Repeat("2", 64)
	cli := &fakeCLI{run: func(args []string) ([]byte, []byte, error) {
		switch args[0] {
		case "info":
			return dockerInfoJSON(true), nil, nil
		case "ps":
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "label=awf.role=worker") {
				return []byte(id + "\n"), nil, nil
			}
			if strings.Contains(joined, "label=awf.role=egress-gateway") {
				return []byte{}, nil, nil
			}
			return nil, nil, errors.New("missing role filter")
		case "network":
			if len(args) >= 2 && args[1] == "ls" {
				return []byte{}, nil, nil
			}
			return nil, nil, errors.New("unexpected network command")
		case "rm":
			if len(args) != 3 || args[1] != "-f" || args[2] != id {
				return nil, nil, errors.New("unexpected rm target")
			}
			return []byte(id + "\n"), nil, nil
		default:
			return nil, nil, errors.New("unexpected command")
		}
	}}
	runtime := newRuntime(t, cli)
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}

	payload, err := runtime.Terminate(context.Background(), server.TerminateRequest{
		RequestID: req.RequestID,
		AttemptID: req.AttemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "\"removed\":true") {
		t.Fatalf("unexpected terminate payload: %s", payload)
	}

	var sawLabelLookup bool
	for _, call := range cli.calls {
		if len(call) > 0 && call[0] == "ps" {
			joined := strings.Join(call, " ")
			if strings.Contains(joined, "label=awf.request_id="+req.RequestID) &&
				strings.Contains(joined, "label=awf.attempt_id="+req.AttemptID) &&
				strings.Contains(joined, "label=awf.role=worker") {
				sawLabelLookup = true
			}
		}
	}
	if !sawLabelLookup {
		t.Fatal("terminate did not resolve container by exact identity labels")
	}
}

func TestTerminateRejectsAmbiguousIdentity(t *testing.T) {
	id1 := strings.Repeat("3", 64)
	id2 := strings.Repeat("4", 64)
	cli := &fakeCLI{run: func(args []string) ([]byte, []byte, error) {
		switch args[0] {
		case "info":
			return dockerInfoJSON(true), nil, nil
		case "ps":
			return []byte(id1 + "\n" + id2 + "\n"), nil, nil
		default:
			return nil, nil, errors.New("unexpected command")
		}
	}}
	runtime := newRuntime(t, cli)
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := runtime.Terminate(context.Background(), server.TerminateRequest{
		RequestID: "req-001",
		AttemptID: "attempt-001",
	}); err == nil {
		t.Fatal("expected ambiguous identity to be rejected")
	}
}

func TestProbeFailsClosedWithoutAppArmor(t *testing.T) {
	cli := &fakeCLI{run: func(args []string) ([]byte, []byte, error) {
		if len(args) > 0 && args[0] == "info" {
			payload, _ := json.Marshal(map[string]any{
				"ServerVersion":   "29.8.1",
				"CgroupVersion":   "2",
				"SecurityOptions": []string{"name=seccomp,profile=builtin", "name=cgroupns"},
			})
			return payload, nil, nil
		}
		return nil, nil, errors.New("unexpected command")
	}}
	runtime := newRuntime(t, cli)
	if err := runtime.Probe(context.Background()); err == nil {
		t.Fatal("expected probe to reject Docker daemon without AppArmor")
	}
	if runtime.Ready() {
		t.Fatal("runtime must remain not ready after failed probe")
	}
}

func TestBrokeredProvisionFailsClosedUntilEgressRuntimeIsWired(t *testing.T) {
	req := testRequest()
	profileID := "llm-default"
	profileHash := strings.Repeat("e", 64)
	routeID := "openai-responses"
	req.Network.Profile = "brokered"
	req.Network.EgressProfileID = &profileID
	req.Network.EgressProfileHash = &profileHash
	req.Network.RouteID = &routeID
	model := "gpt-5.2"
	req.Network.Model = &model

	cli := provisionCLI(t, req, nil)
	runtime := newRuntime(t, cli)
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Provision(context.Background(), req); !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("expected brokered runtime to fail closed as unavailable, got %v", err)
	}
	for _, call := range cli.calls {
		if len(call) > 0 && call[0] == "create" {
			t.Fatal("brokered request reached docker create before egress runtime was wired")
		}
	}
}
