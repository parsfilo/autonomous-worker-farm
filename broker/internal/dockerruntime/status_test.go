package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"autonomous-worker/broker/internal/server"
)

type statusCLI struct {
	containerID string
	running     bool
	exitCode    int
	stdout      []byte
	stderr      []byte
	psOutput    string
}

func (c *statusCLI) Run(_ context.Context, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, errors.New("missing docker args")
	}
	switch args[0] {
	case "ps":
		return []byte(c.psOutput), nil, nil
	case "inspect":
		var actual inspectContainer
		actual.ID = c.containerID
		actual.Config.Labels = map[string]string{
			"awf.role":       "worker",
			"awf.request_id": "request-001",
			"awf.attempt_id": "attempt-001",
		}
		actual.State.Running = c.running
		actual.State.ExitCode = c.exitCode
		payload, err := json.Marshal([]inspectContainer{actual})
		return payload, nil, err
	case "logs":
		return c.stdout, c.stderr, nil
	default:
		return nil, nil, errors.New("unexpected docker command")
	}
}

func statusRuntime(cli CLI) *Runtime {
	return &Runtime{
		cfg: Config{
			MachineID: "production-vps",
			Clock: func() time.Time {
				return time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
			},
		},
		cli:   cli,
		ready: true,
	}
}

func TestStatusReportsRunningWorkerWithBoundedLogs(t *testing.T) {
	id := strings.Repeat("a", 64)
	cli := &statusCLI{
		containerID: id,
		running:     true,
		stdout:      []byte("worker stdout\n"),
		stderr:      []byte("worker stderr\n"),
		psOutput:    id + "\n",
	}
	runtime := statusRuntime(cli)

	payload, err := runtime.Status(context.Background(), server.AttemptStatusRequest{
		RequestID: "request-001",
		AttemptID: "attempt-001",
	})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result["state"] != "RUNNING" ||
		result["running"] != true ||
		result["exit_code"] != nil ||
		result["stdout_tail"] != "worker stdout\n" ||
		result["stderr_tail"] != "worker stderr\n" {
		t.Fatalf("unexpected running status: %v", result)
	}
}

func TestStatusReportsExitedWorker(t *testing.T) {
	id := strings.Repeat("b", 64)
	runtime := statusRuntime(&statusCLI{
		containerID: id,
		running:     false,
		exitCode:    17,
		psOutput:    id + "\n",
	})

	payload, err := runtime.Status(context.Background(), server.AttemptStatusRequest{
		RequestID: "request-001",
		AttemptID: "attempt-001",
	})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result["state"] != "EXITED" || result["running"] != false || result["exit_code"] != float64(17) {
		t.Fatalf("unexpected exited status: %v", result)
	}
}

func TestStatusReturnsNotFoundWithoutInspect(t *testing.T) {
	runtime := statusRuntime(&statusCLI{psOutput: ""})
	payload, err := runtime.Status(context.Background(), server.AttemptStatusRequest{
		RequestID: "request-001",
		AttemptID: "attempt-001",
	})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result["state"] != "NOT_FOUND" || result["container_id"] != nil {
		t.Fatalf("unexpected not-found status: %v", result)
	}
}

func TestStatusRejectsAmbiguousWorkerLookup(t *testing.T) {
	id1 := strings.Repeat("c", 64)
	id2 := strings.Repeat("d", 64)
	runtime := statusRuntime(&statusCLI{psOutput: id1 + "\n" + id2 + "\n"})
	if _, err := runtime.Status(context.Background(), server.AttemptStatusRequest{
		RequestID: "request-001",
		AttemptID: "attempt-001",
	}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous lookup rejection, got %v", err)
	}
}

func TestBoundedTailKeepsOnlyLastBytes(t *testing.T) {
	got := boundedTail([]byte("0123456789"), 4)
	if got != "6789" {
		t.Fatalf("bounded tail = %q, want 6789", got)
	}
}
