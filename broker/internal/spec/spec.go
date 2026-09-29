package spec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const WorkerUID = 65532

var (
	idPattern               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dockerObjectNamePattern = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
)

type Request struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	TaskID        string `json:"task_id"`
	AttemptID     string `json:"attempt_id"`
	MachineID     string `json:"machine_id"`
	Tier          string `json:"tier"`
	RunRoot       string `json:"run_root"`
	Workspace     struct {
		Source        string `json:"source"`
		MountPath     string `json:"mount_path"`
		ReadOnly      bool   `json:"read_only"`
		BaseSHA       string `json:"base_sha"`
		ControllerGID uint32 `json:"controller_gid"`
	} `json:"workspace"`
	Image struct {
		Reference string `json:"reference"`
		Digest    string `json:"digest"`
	} `json:"image"`
	Network struct {
		Profile           string  `json:"profile"`
		EgressProfileID   *string `json:"egress_profile_id"`
		EgressProfileHash *string `json:"egress_profile_hash"`
		RouteID           *string `json:"route_id"`
		Model             *string `json:"model"`
	} `json:"network"`
	Resources struct {
		CPU            float64 `json:"cpu"`
		MemoryBytes    int64   `json:"memory_bytes"`
		PIDs           int     `json:"pids"`
		TmpfsBytes     int64   `json:"tmpfs_bytes"`
		TimeoutSeconds int     `json:"timeout_seconds"`
	} `json:"resources"`
	Command struct {
		Argv         []string `json:"argv"`
		EnvAllowlist []string `json:"env_allowlist"`
	} `json:"command"`
	PolicyHash         string `json:"policy_hash"`
	ExpiresAt          string `json:"expires_at"`
	WorkspaceLeaseID   string `json:"workspace_lease_id"`
	WorkspaceLeaseHash string `json:"workspace_lease_hash"`
}

type Mount struct {
	Source      string
	Destination string
	ReadOnly    bool
}

type DockerSpec struct {
	ContainerName       string
	CreateArgs          []string
	ExpectedImage       string
	ExpectedNetworkMode string
	ProcessUID          int
	ProcessGID          int
	Mounts              []Mount
}

type Limits struct {
	MaxCPU           float64
	MaxMemoryBytes   int64
	MaxPIDs          int
	MaxTimeout       time.Duration
	MaxRequestFuture time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxCPU:           4,
		MaxMemoryBytes:   8 << 30,
		MaxPIDs:          1024,
		MaxTimeout:       2 * time.Hour,
		MaxRequestFuture: 10 * time.Minute,
	}
}

func under(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}

func pinnedImage(ref, digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", errors.New("invalid image digest")
	}
	if strings.ContainsAny(ref, " \t\r\n") || ref == "" {
		return "", errors.New("invalid image reference")
	}
	if strings.Contains(ref, "@") {
		parts := strings.SplitN(ref, "@", 2)
		if parts[0] == "" || parts[1] != digest {
			return "", errors.New("image reference digest mismatch")
		}
		return ref, nil
	}
	return ref + "@" + digest, nil
}

func ValidateRequest(req Request, runsRoot string, now time.Time, limits Limits) error {
	if req.SchemaVersion != "1.0" {
		return errors.New("unsupported schema_version")
	}
	for name, value := range map[string]string{
		"request_id": req.RequestID,
		"task_id":    req.TaskID,
		"attempt_id": req.AttemptID,
		"machine_id": req.MachineID,
	} {
		if !idPattern.MatchString(value) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if req.Tier != "T1" {
		return errors.New("phase 1 broker supports T1 only")
	}
	switch req.Network.Profile {
	case "none":
		if req.Network.EgressProfileID != nil || req.Network.EgressProfileHash != nil ||
			req.Network.RouteID != nil || req.Network.Model != nil {
			return errors.New("network:none must not bind an egress profile/model")
		}
	case "brokered":
		if req.Network.EgressProfileID == nil || !idPattern.MatchString(*req.Network.EgressProfileID) {
			return errors.New("invalid brokered egress_profile_id")
		}
		if req.Network.EgressProfileHash == nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(*req.Network.EgressProfileHash) {
			return errors.New("invalid brokered egress_profile_hash")
		}
		if req.Network.RouteID == nil || !idPattern.MatchString(*req.Network.RouteID) {
			return errors.New("invalid brokered route_id")
		}
		if req.Network.Model == nil || *req.Network.Model == "" || len(*req.Network.Model) > 256 {
			return errors.New("invalid brokered model")
		}
	default:
		return errors.New("unsupported network profile")
	}
	runsRoot = filepath.Clean(runsRoot)
	runRoot := filepath.Clean(req.RunRoot)
	if !under(runsRoot, runRoot) || runRoot == runsRoot {
		return errors.New("run_root outside approved broker runs directory")
	}
	expectedRunRoot := filepath.Join(runsRoot, req.AttemptID)
	if runRoot != expectedRunRoot {
		return errors.New("run_root must be derived from attempt_id")
	}
	expectedRepo := filepath.Join(runRoot, "repo")
	if filepath.Clean(req.Workspace.Source) != expectedRepo || req.Workspace.MountPath != "/workspace" {
		return errors.New("workspace source/mount mismatch")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(req.Workspace.BaseSHA) {
		return errors.New("invalid base_sha")
	}
	if req.Workspace.ControllerGID == 0 {
		return errors.New("invalid workspace controller_gid")
	}
	if _, err := pinnedImage(req.Image.Reference, req.Image.Digest); err != nil {
		return err
	}
	if req.Resources.CPU <= 0 || req.Resources.CPU > limits.MaxCPU {
		return errors.New("cpu limit out of range")
	}
	if req.Resources.MemoryBytes < 64<<20 || req.Resources.MemoryBytes > limits.MaxMemoryBytes {
		return errors.New("memory limit out of range")
	}
	if req.Resources.PIDs < 16 || req.Resources.PIDs > limits.MaxPIDs {
		return errors.New("pids limit out of range")
	}
	if req.Resources.TimeoutSeconds <= 0 || time.Duration(req.Resources.TimeoutSeconds)*time.Second > limits.MaxTimeout {
		return errors.New("timeout out of range")
	}
	fixedCommand := []string{
		"opencode", "run", "--standalone", "--format", "json", "--agent", "build", "--title", "AWF Worker", "--file", "control/task.md",
		"Execute the task described in the attached task file. Work only in repo/.",
	}
	if len(req.Command.Argv) != len(fixedCommand) {
		return errors.New("phase 1 broker command argv must match the fixed OpenCode command")
	}
	for i := range fixedCommand {
		if req.Command.Argv[i] != fixedCommand[i] {
			return errors.New("phase 1 broker command argv must match the fixed OpenCode command")
		}
	}
	expires, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		return errors.New("invalid expires_at")
	}
	if !expires.After(now) || expires.Sub(now) > limits.MaxRequestFuture {
		return errors.New("expires_at outside accepted window")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(req.PolicyHash) {
		return errors.New("invalid policy_hash")
	}
	if !idPattern.MatchString(req.WorkspaceLeaseID) {
		return errors.New("invalid workspace_lease_id")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(req.WorkspaceLeaseHash) {
		return errors.New("invalid workspace_lease_hash")
	}
	return nil
}

func BuildDockerSpec(req Request, runsRoot string, now time.Time, limits Limits) (DockerSpec, error) {
	if req.Network.Profile != "none" {
		return DockerSpec{}, errors.New("offline Docker spec requires network:none")
	}
	return buildDockerSpec(req, runsRoot, now, limits, "none")
}

func BuildBrokeredWorkerDockerSpec(
	req Request,
	runsRoot string,
	now time.Time,
	limits Limits,
	internalNetwork string,
) (DockerSpec, error) {
	if req.Network.Profile != "brokered" {
		return DockerSpec{}, errors.New("brokered worker Docker spec requires network:brokered")
	}
	if !dockerObjectNamePattern.MatchString(internalNetwork) {
		return DockerSpec{}, errors.New("invalid brokered internal network name")
	}
	return buildDockerSpec(req, runsRoot, now, limits, internalNetwork)
}

func buildDockerSpec(
	req Request,
	runsRoot string,
	now time.Time,
	limits Limits,
	networkMode string,
) (DockerSpec, error) {
	if err := ValidateRequest(req, runsRoot, now, limits); err != nil {
		return DockerSpec{}, err
	}
	image, err := pinnedImage(req.Image.Reference, req.Image.Digest)
	if err != nil {
		return DockerSpec{}, err
	}

	runRoot := filepath.Clean(req.RunRoot)
	repo := filepath.Join(runRoot, "repo")
	control := filepath.Join(runRoot, "control")
	artifacts := filepath.Join(runRoot, "artifacts")
	for _, path := range []string{repo, control, artifacts} {
		if !under(runRoot, path) {
			return DockerSpec{}, errors.New("derived mount escaped run_root")
		}
	}

	mounts := []Mount{
		{Source: runRoot, Destination: "/run", ReadOnly: true},
		{Source: repo, Destination: "/run/repo", ReadOnly: req.Workspace.ReadOnly},
		{Source: control, Destination: "/run/control", ReadOnly: true},
		{Source: artifacts, Destination: "/run/artifacts", ReadOnly: false},
	}
	mountArg := func(m Mount) string {
		value := "type=bind,src=" + m.Source + ",dst=" + m.Destination
		if m.ReadOnly {
			value += ",readonly"
		}
		return value
	}

	name := boundedDockerName("awf-worker", req.AttemptID)
	args := []string{
		"create",
		"--name", name,
		"--label", "awf.role=worker",
		"--label", "awf.request_id=" + req.RequestID,
		"--label", "awf.task_id=" + req.TaskID,
		"--label", "awf.attempt_id=" + req.AttemptID,
		"--label", "awf.workspace_lease_id=" + req.WorkspaceLeaseID,
		"--network", networkMode,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", strconv.Itoa(req.Resources.PIDs),
		"--memory", strconv.FormatInt(req.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(req.Resources.CPU, 'f', -1, 64),
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + strconv.FormatInt(req.Resources.TmpfsBytes, 10) + ",mode=1777",
		"--tmpfs", "/home/worker:rw,nosuid,nodev,size=67108864,uid=" + strconv.Itoa(WorkerUID) + ",gid=" + strconv.FormatUint(uint64(req.Workspace.ControllerGID), 10) + ",mode=0700",
		"--user", strconv.Itoa(WorkerUID) + ":" + strconv.FormatUint(uint64(req.Workspace.ControllerGID), 10),
		"--workdir", "/run",
	}
	for _, m := range mounts {
		args = append(args, "--mount", mountArg(m))
	}
	args = append(args,
		"--env", "HOME=/home/worker",
		"--env", "XDG_CONFIG_HOME=/tmp/.config",
		"--env", "XDG_CACHE_HOME=/tmp/.cache",
		"--env", "XDG_DATA_HOME=/tmp/.local/share",
		"--env", "TMPDIR=/tmp",
		"--env", "OPENCODE_DISABLE_PROJECT_CONFIG=1",
		"--env", "OPENCODE_CONFIG_DIR=/run/control/opencode",
		"--env", "OPENCODE_DB=:memory:",
		"--env", "AWF_REPO_DIR=/run/repo",
		"--env", "AWF_ARTIFACT_DIR=/run/artifacts",
		"--env", "AWF_TASK_ID="+req.TaskID,
		"--env", "AWF_ATTEMPT_ID="+req.AttemptID,
		"--env", "GIT_CONFIG_COUNT=1",
		"--env", "GIT_CONFIG_KEY_0=safe.directory",
		"--env", "GIT_CONFIG_VALUE_0=/run/repo",
		"--env", "GIT_TERMINAL_PROMPT=0",
		image,
	)
	args = append(args, req.Command.Argv...)

	return DockerSpec{
		ContainerName:       name,
		CreateArgs:          args,
		ExpectedImage:       image,
		ExpectedNetworkMode: networkMode,
		ProcessUID:          WorkerUID,
		ProcessGID:          int(req.Workspace.ControllerGID),
		Mounts:              mounts,
	}, nil
}

func boundedDockerName(prefix, identity string) string {
	safe := strings.ToLower(regexp.MustCompile("[^a-zA-Z0-9_.-]").ReplaceAllString(identity, "-"))
	sum := sha256.Sum256([]byte(identity))
	suffix := hex.EncodeToString(sum[:6])
	maxIdentity := 63 - len(prefix) - len(suffix) - 2
	if maxIdentity < 1 {
		maxIdentity = 1
	}
	if len(safe) > maxIdentity {
		safe = safe[:maxIdentity]
	}
	return prefix + "-" + safe + "-" + suffix
}

func BindingHash(req Request) string {
	var buf bytes.Buffer
	buf.WriteString("awf-sandbox-request-v1\n")
	writeBindingField(&buf, "schema_version", req.SchemaVersion)
	writeBindingField(&buf, "request_id", req.RequestID)
	writeBindingField(&buf, "task_id", req.TaskID)
	writeBindingField(&buf, "attempt_id", req.AttemptID)
	writeBindingField(&buf, "machine_id", req.MachineID)
	writeBindingField(&buf, "tier", req.Tier)
	writeBindingField(&buf, "run_root", req.RunRoot)
	writeBindingField(&buf, "workspace.source", req.Workspace.Source)
	writeBindingField(&buf, "workspace.mount_path", req.Workspace.MountPath)
	if req.Workspace.ReadOnly {
		writeBindingField(&buf, "workspace.read_only", "1")
	} else {
		writeBindingField(&buf, "workspace.read_only", "0")
	}
	writeBindingField(&buf, "workspace.base_sha", req.Workspace.BaseSHA)
	writeBindingField(&buf, "workspace.controller_gid", strconv.FormatUint(uint64(req.Workspace.ControllerGID), 10))
	writeBindingField(&buf, "image.reference", req.Image.Reference)
	writeBindingField(&buf, "image.digest", req.Image.Digest)
	writeBindingField(&buf, "network.profile", req.Network.Profile)
	writeBindingField(&buf, "network.egress_profile_id", nullableString(req.Network.EgressProfileID))
	writeBindingField(&buf, "network.egress_profile_hash", nullableString(req.Network.EgressProfileHash))
	writeBindingField(&buf, "network.route_id", nullableString(req.Network.RouteID))
	writeBindingField(&buf, "network.model", nullableString(req.Network.Model))
	writeBindingField(&buf, "resources.cpu", strconv.FormatFloat(req.Resources.CPU, 'f', -1, 64))
	writeBindingField(&buf, "resources.memory_bytes", strconv.FormatInt(req.Resources.MemoryBytes, 10))
	writeBindingField(&buf, "resources.pids", strconv.Itoa(req.Resources.PIDs))
	writeBindingField(&buf, "resources.tmpfs_bytes", strconv.FormatInt(req.Resources.TmpfsBytes, 10))
	writeBindingField(&buf, "resources.timeout_seconds", strconv.Itoa(req.Resources.TimeoutSeconds))
	writeBindingField(&buf, "command.argv.count", strconv.Itoa(len(req.Command.Argv)))
	for i, value := range req.Command.Argv {
		writeBindingField(&buf, "command.argv."+strconv.Itoa(i), value)
	}
	writeBindingField(&buf, "command.env_allowlist.count", strconv.Itoa(len(req.Command.EnvAllowlist)))
	for i, value := range req.Command.EnvAllowlist {
		writeBindingField(&buf, "command.env_allowlist."+strconv.Itoa(i), value)
	}
	writeBindingField(&buf, "policy_hash", req.PolicyHash)
	writeBindingField(&buf, "expires_at", req.ExpiresAt)
	writeBindingField(&buf, "workspace_lease_id", req.WorkspaceLeaseID)
	writeBindingField(&buf, "workspace_lease_hash", req.WorkspaceLeaseHash)

	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

func writeBindingField(buf *bytes.Buffer, name, value string) {
	valueBytes := []byte(value)
	buf.WriteString(name)
	buf.WriteByte('=')
	buf.WriteString(strconv.Itoa(len(valueBytes)))
	buf.WriteByte(':')
	buf.Write(valueBytes)
	buf.WriteByte('\n')
}

func nullableString(value *string) string {
	if value == nil {
		return "<null>"
	}
	return *value
}
