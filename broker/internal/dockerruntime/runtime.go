package dockerruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"autonomous-worker/broker/internal/server"
	"autonomous-worker/broker/internal/spec"
)

var containerIDPattern = regexp.MustCompile("^[0-9a-f]{12,64}$")

type CLI interface {
	Run(context.Context, ...string) ([]byte, []byte, error)
}

type ExecCLI struct {
	Binary string
}

func (c ExecCLI) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	binary := c.Binary
	if binary == "" {
		binary = "/usr/bin/docker"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	var stdout strings.Builder
	var stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return []byte(stdout.String()), []byte(stderr.String()), err
}

type Config struct {
	RunsRoot        string
	BrokerBuild     string
	MachineID       string
	RequireRoot     bool
	Clock           func() time.Time
	EgressProfiles  EgressProfileStore
	ProviderSecrets ProviderSecretStore
}

type Runtime struct {
	cfg Config
	cli CLI

	mu        sync.RWMutex
	ready     bool
	dockerVer string
	seccomp   bool
	cgroupsV2 bool
	apparmor  bool
}

type dockerInfo struct {
	ServerVersion   string   `json:"ServerVersion"`
	CgroupVersion   string   `json:"CgroupVersion"`
	SecurityOptions []string `json:"SecurityOptions"`
}

type inspectContainer struct {
	ID     string `json:"Id"`
	Image  string `json:"Image"`
	Config struct {
		Image  string            `json:"Image"`
		User   string            `json:"User"`
		Labels map[string]string `json:"Labels"`
		Env    []string          `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode    string                       `json:"NetworkMode"`
		ReadonlyRootfs bool                         `json:"ReadonlyRootfs"`
		Privileged     bool                         `json:"Privileged"`
		CapDrop        []string                     `json:"CapDrop"`
		SecurityOpt    []string                     `json:"SecurityOpt"`
		PidsLimit      int64                        `json:"PidsLimit"`
		Memory         int64                        `json:"Memory"`
		NanoCPUs       int64                        `json:"NanoCpus"`
		Tmpfs          map[string]string            `json:"Tmpfs"`
		Devices        []json.RawMessage            `json:"Devices"`
		DeviceRequests []json.RawMessage            `json:"DeviceRequests"`
		PortBindings   map[string][]json.RawMessage `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			Aliases []string `json:"Aliases"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	State struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	} `json:"State"`
}

type attestation struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	TaskID        string `json:"task_id"`
	AttemptID     string `json:"attempt_id"`
	MachineID     string `json:"machine_id"`
	Status        string `json:"status"`
	Tier          string `json:"tier"`
	Broker        struct {
		Kind  string `json:"kind"`
		Build string `json:"build"`
	} `json:"broker"`
	Sandbox struct {
		LandlockABI                     *int   `json:"landlock_abi"`
		ContainerRuntime                string `json:"container_runtime"`
		UserNamespace                   bool   `json:"user_namespace"`
		Seccomp                         bool   `json:"seccomp"`
		AppArmor                        bool   `json:"apparmor"`
		Cgroups                         bool   `json:"cgroups"`
		NetworkProfile                  string `json:"network_profile"`
		NetworkEnforced                 bool   `json:"network_enforced"`
		RemoteGitWriteCredentialPresent bool   `json:"remote_git_write_credential_present"`
		DockerSocketPresent             bool   `json:"docker_socket_present"`
		HostHomeMounted                 bool   `json:"host_home_mounted"`
		ProcessUID                      int    `json:"process_uid"`
		ProcessGID                      int    `json:"process_gid"`
		CapabilitiesDropped             bool   `json:"capabilities_dropped"`
		ReadOnlyRootfs                  bool   `json:"read_only_rootfs"`
		NoNewPrivileges                 bool   `json:"no_new_privileges"`
	} `json:"sandbox"`
	Egress        any            `json:"egress"`
	ImageDigest   string         `json:"image_digest"`
	ContainerID   *string        `json:"container_id"`
	StartedAt     string         `json:"started_at"`
	EndedAt       *string        `json:"ended_at"`
	ExitCode      *int           `json:"exit_code"`
	RequestHash   string         `json:"request_hash"`
	EvidenceHash  *string        `json:"evidence_hash"`
	RejectionCode *string        `json:"rejection_code"`
	Details       map[string]any `json:"details"`
}

func New(cfg Config, cli CLI) (*Runtime, error) {
	if cfg.RunsRoot == "" || cfg.BrokerBuild == "" || cfg.MachineID == "" {
		return nil, errors.New("runs root, broker build and machine id are required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cli == nil {
		cli = ExecCLI{}
	}
	return &Runtime{cfg: cfg, cli: cli}, nil
}

func (r *Runtime) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ready
}

func (r *Runtime) Probe(ctx context.Context) error {
	if r.cfg.RequireRoot && os.Geteuid() != 0 {
		return errors.New("docker runtime probe requires root broker identity")
	}
	stdout, stderr, err := r.cli.Run(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return fmt.Errorf("docker info failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	var info dockerInfo
	if err := json.Unmarshal(stdout, &info); err != nil {
		return fmt.Errorf("decode docker info: %w", err)
	}
	seccomp := false
	apparmor := false
	for _, option := range info.SecurityOptions {
		if strings.Contains(option, "name=seccomp") {
			seccomp = true
		}
		if strings.Contains(option, "name=apparmor") {
			apparmor = true
		}
	}
	cgroupsV2 := info.CgroupVersion == "2"
	if info.ServerVersion == "" || !seccomp || !apparmor || !cgroupsV2 {
		return errors.New("docker daemon does not satisfy required security profile")
	}

	r.mu.Lock()
	r.dockerVer = info.ServerVersion
	r.seccomp = seccomp
	r.cgroupsV2 = cgroupsV2
	r.apparmor = apparmor
	r.ready = true
	r.mu.Unlock()
	return nil
}

func (r *Runtime) Provision(ctx context.Context, req spec.Request) (json.RawMessage, error) {
	if !r.Ready() {
		return nil, server.ErrUnavailable
	}
	if req.MachineID != r.cfg.MachineID {
		return nil, errors.New("request machine_id does not match runtime")
	}
	switch req.Network.Profile {
	case "none":
		return r.provisionOffline(ctx, req)
	case "brokered":
		return r.provisionBrokered(ctx, req)
	default:
		return nil, errors.New("unsupported network profile")
	}
}

func (r *Runtime) provisionOffline(ctx context.Context, req spec.Request) (json.RawMessage, error) {
	dockerSpec, err := spec.BuildDockerSpec(req, r.cfg.RunsRoot, r.cfg.Clock(), spec.DefaultLimits())
	if err != nil {
		return nil, err
	}
	if err := r.verifyPinnedImage(ctx, dockerSpec.ExpectedImage, req.Image.Digest); err != nil {
		return nil, err
	}

	stdout, stderr, err := r.cli.Run(ctx, dockerSpec.CreateArgs...)
	if err != nil {
		return nil, fmt.Errorf("docker create failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	containerID := strings.TrimSpace(string(stdout))
	if !containerIDPattern.MatchString(containerID) {
		return nil, errors.New("docker create returned invalid container id")
	}

	cleanup := true
	defer func() {
		if cleanup {
			_, _, _ = r.cli.Run(context.Background(), "rm", "-f", containerID)
		}
	}()

	inspect, err := r.inspect(ctx, containerID)
	if err != nil {
		return nil, err
	}
	if err := r.verifyInspect(req, dockerSpec, inspect); err != nil {
		return nil, err
	}

	if _, stderr, err := r.cli.Run(ctx, "start", containerID); err != nil {
		return nil, fmt.Errorf("docker start failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}

	r.mu.RLock()
	dockerVer := r.dockerVer
	seccomp := r.seccomp
	cgroups := r.cgroupsV2
	r.mu.RUnlock()

	out := attestation{
		SchemaVersion: "1.0",
		RequestID:     req.RequestID,
		TaskID:        req.TaskID,
		AttemptID:     req.AttemptID,
		MachineID:     req.MachineID,
		Status:        "PROVISIONED",
		Tier:          req.Tier,
		ImageDigest:   req.Image.Digest,
		ContainerID:   &containerID,
		StartedAt:     r.cfg.Clock().UTC().Format(time.RFC3339Nano),
		RequestHash:   spec.BindingHash(req),
		Details: map[string]any{
			"pids_limit":   req.Resources.PIDs,
			"memory_bytes": req.Resources.MemoryBytes,
			"cpu":          req.Resources.CPU,
		},
	}
	out.Egress = nil
	out.Broker.Kind = "privileged-docker"
	out.Broker.Build = r.cfg.BrokerBuild
	out.Sandbox.ContainerRuntime = "docker-" + dockerVer
	out.Sandbox.UserNamespace = false
	out.Sandbox.Seccomp = seccomp
	out.Sandbox.AppArmor = r.apparmor
	out.Sandbox.Cgroups = cgroups
	out.Sandbox.NetworkProfile = "none"
	out.Sandbox.NetworkEnforced = true
	out.Sandbox.RemoteGitWriteCredentialPresent = false
	out.Sandbox.DockerSocketPresent = false
	out.Sandbox.HostHomeMounted = false
	out.Sandbox.ProcessUID = spec.WorkerUID
	out.Sandbox.ProcessGID = int(req.Workspace.ControllerGID)
	out.Sandbox.CapabilitiesDropped = true
	out.Sandbox.ReadOnlyRootfs = true
	out.Sandbox.NoNewPrivileges = true

	payload, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal sandbox attestation: %w", err)
	}

	cleanup = false
	return payload, nil
}

func (r *Runtime) Terminate(ctx context.Context, req server.TerminateRequest) (json.RawMessage, error) {
	if !r.Ready() {
		return nil, server.ErrUnavailable
	}
	return r.terminateAttempt(ctx, req)
}

func (r *Runtime) verifyPinnedImage(ctx context.Context, imageRef, expectedDigest string) error {
	stdout, stderr, err := r.cli.Run(ctx, "image", "inspect", imageRef, "--format", "{{json .RepoDigests}}")
	if err != nil {
		return fmt.Errorf("pinned worker image is not available locally: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	var repoDigests []string
	if err := json.Unmarshal(stdout, &repoDigests); err != nil {
		return fmt.Errorf("decode image RepoDigests: %w", err)
	}
	for _, value := range repoDigests {
		if strings.HasSuffix(value, "@"+expectedDigest) {
			return nil
		}
	}
	return errors.New("local worker image does not match requested digest")
}

func (r *Runtime) inspect(ctx context.Context, containerID string) (inspectContainer, error) {
	stdout, stderr, err := r.cli.Run(ctx, "inspect", containerID)
	if err != nil {
		return inspectContainer{}, fmt.Errorf("docker inspect failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	var values []inspectContainer
	if err := json.Unmarshal(stdout, &values); err != nil {
		return inspectContainer{}, fmt.Errorf("decode docker inspect: %w", err)
	}
	if len(values) != 1 {
		return inspectContainer{}, errors.New("docker inspect returned unexpected container count")
	}
	return values[0], nil
}

func (r *Runtime) verifyInspect(req spec.Request, expected spec.DockerSpec, actual inspectContainer) error {
	if actual.ID == "" || !containerIDPattern.MatchString(actual.ID) {
		return errors.New("inspect container id is invalid")
	}
	if actual.Config.Image != expected.ExpectedImage {
		return errors.New("inspect image reference differs from pinned spec")
	}
	if actual.Config.User != strconv.Itoa(spec.WorkerUID)+":"+strconv.FormatUint(uint64(req.Workspace.ControllerGID), 10) {
		return errors.New("container user is not the required non-root UID")
	}
	if actual.Config.Labels["awf.request_id"] != req.RequestID ||
		actual.Config.Labels["awf.task_id"] != req.TaskID ||
		actual.Config.Labels["awf.attempt_id"] != req.AttemptID ||
		actual.Config.Labels["awf.workspace_lease_id"] != req.WorkspaceLeaseID {
		return errors.New("container identity labels do not match request")
	}
	if actual.HostConfig.NetworkMode != expected.ExpectedNetworkMode ||
		!actual.HostConfig.ReadonlyRootfs ||
		actual.HostConfig.Privileged {
		return errors.New("container network/rootfs/privileged settings do not match policy")
	}
	if !contains(actual.HostConfig.CapDrop, "ALL") {
		return errors.New("container does not drop all capabilities")
	}
	if !contains(actual.HostConfig.SecurityOpt, "no-new-privileges:true") {
		return errors.New("container lacks no-new-privileges")
	}
	if actual.HostConfig.PidsLimit != int64(req.Resources.PIDs) ||
		actual.HostConfig.Memory != req.Resources.MemoryBytes {
		return errors.New("container resource limits differ from request")
	}
	expectedNanoCPU := int64(req.Resources.CPU * 1_000_000_000)
	if actual.HostConfig.NanoCPUs != expectedNanoCPU {
		return errors.New("container CPU limit differs from request")
	}
	if len(actual.HostConfig.Devices) != 0 || len(actual.HostConfig.DeviceRequests) != 0 {
		return errors.New("container has forbidden host device access")
	}
	if len(actual.HostConfig.PortBindings) != 0 {
		return errors.New("container has forbidden published port bindings")
	}
	if containsSensitiveEnv(actual.Config.Env) {
		return errors.New("container environment contains a secret-like credential")
	}
	if expected.ExpectedNetworkMode == "none" {
		if len(actual.NetworkSettings.Networks) != 0 {
			return errors.New("network:none container has attached Docker networks")
		}
	} else {
		if len(actual.NetworkSettings.Networks) != 1 {
			return errors.New("brokered worker must have exactly one Docker network")
		}
		if _, ok := actual.NetworkSettings.Networks[expected.ExpectedNetworkMode]; !ok {
			return errors.New("brokered worker is attached to an unexpected Docker network")
		}
	}
	if _, ok := actual.HostConfig.Tmpfs["/tmp"]; !ok {
		return errors.New("container /tmp tmpfs is missing")
	}
	if _, ok := actual.HostConfig.Tmpfs["/home/worker"]; !ok {
		return errors.New("container worker HOME tmpfs is missing")
	}

	expectedMounts := make(map[string]spec.Mount, len(expected.Mounts))
	for _, mount := range expected.Mounts {
		expectedMounts[mount.Destination] = mount
	}
	if len(actual.Mounts) != len(expectedMounts) {
		return errors.New("container has unexpected mount count")
	}
	for _, mount := range actual.Mounts {
		want, ok := expectedMounts[mount.Destination]
		if !ok {
			return errors.New("container has unexpected bind mount destination")
		}
		if mount.Type != "bind" ||
			mount.Source != want.Source ||
			mount.RW == want.ReadOnly {
			return errors.New("container bind mount differs from policy")
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
