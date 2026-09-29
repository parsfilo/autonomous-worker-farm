package dockerruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"autonomous-worker/broker/internal/egressprofile"
	"autonomous-worker/broker/internal/egresstopology"
	"autonomous-worker/broker/internal/server"
	"autonomous-worker/broker/internal/spec"
)

type EgressProfileStore interface {
	Load(string) (egressprofile.Loaded, error)
}

type ProviderSecretStore interface {
	Stage(secretHandle, attemptID string) (string, error)
	Cleanup(attemptID string) error
}

type inspectNetwork struct {
	Name     string
	Id       string
	Driver   string
	Internal bool
	Labels   map[string]string
}

type brokeredResources struct {
	internalNetworkCreated bool
	egressNetworkCreated   bool
	internalNetworkName    string
	egressNetworkName      string
	gatewayContainerID     string
	workerContainerID      string
	secretStaged           bool
	tokenCreated           bool
}

func (r *Runtime) provisionBrokered(ctx context.Context, req spec.Request) (json.RawMessage, error) {
	if r.cfg.EgressProfiles == nil {
		return nil, server.ErrUnavailable
	}
	if err := spec.ValidateRequest(req, r.cfg.RunsRoot, r.cfg.Clock(), spec.DefaultLimits()); err != nil {
		return nil, err
	}
	if req.Network.EgressProfileID == nil ||
		req.Network.EgressProfileHash == nil ||
		req.Network.RouteID == nil ||
		req.Network.Model == nil {
		return nil, errors.New("brokered network binding is incomplete")
	}

	loaded, err := r.cfg.EgressProfiles.Load(*req.Network.EgressProfileID)
	if err != nil {
		return nil, fmt.Errorf("load trusted egress profile: %w", err)
	}
	if loaded.Profile.ProfileID != *req.Network.EgressProfileID {
		return nil, errors.New("trusted egress profile id binding mismatch")
	}
	if loaded.Hash != *req.Network.EgressProfileHash {
		return nil, errors.New("trusted egress profile hash binding mismatch")
	}
	route, err := loaded.Resolve(*req.Network.RouteID, *req.Network.Model)
	if err != nil {
		return nil, err
	}
	isFreeConnect := route.Protocol == "opencode-free-connect"
	if !isFreeConnect && r.cfg.ProviderSecrets == nil {
		return nil, server.ErrUnavailable
	}

	resources := brokeredResources{}
	success := false
	defer func() {
		if !success {
			r.cleanupBrokeredResources(context.Background(), req, resources)
		}
	}()

	providerSecretPath := ""
	attemptTokenPath := ""
	attemptTokenHash := ""
	if !isFreeConnect {
		if route.SecretHandle == nil {
			return nil, errors.New("secret-backed route is missing secret handle")
		}
		providerSecretPath, err = r.cfg.ProviderSecrets.Stage(*route.SecretHandle, req.AttemptID)
		if err != nil {
			return nil, fmt.Errorf("stage gateway provider secret: %w", err)
		}
		resources.secretStaged = true

		attemptTokenPath, attemptTokenHash, err = r.createAttemptToken(req)
		if err != nil {
			return nil, err
		}
		resources.tokenCreated = true
	}

	plan, err := egresstopology.Compile(egresstopology.CompileInput{
		Request:            req,
		LoadedProfile:      loaded,
		RunsRoot:           r.cfg.RunsRoot,
		ProviderSecretPath: providerSecretPath,
		AttemptTokenPath:   attemptTokenPath,
		AttemptTokenSHA256: attemptTokenHash,
		Now:                r.cfg.Clock(),
		Limits:             spec.DefaultLimits(),
	})
	if err != nil {
		return nil, fmt.Errorf("compile brokered egress topology: %w", err)
	}
	resources.internalNetworkName = plan.InternalNetworkName
	resources.egressNetworkName = plan.EgressNetworkName

	if err := r.verifyPinnedImage(ctx, plan.Worker.ExpectedImage, req.Image.Digest); err != nil {
		return nil, err
	}
	if err := r.verifyPinnedImage(
		ctx,
		plan.Gateway.ExpectedImage,
		loaded.Profile.GatewayImage.Digest,
	); err != nil {
		return nil, fmt.Errorf("verify pinned gateway image: %w", err)
	}

	internalNetworkID, err := r.createAndVerifyNetwork(
		ctx,
		plan.InternalNetworkCreateArgs,
		plan.InternalNetworkName,
		true,
		req,
		loaded.Hash,
	)
	if err != nil {
		return nil, err
	}
	resources.internalNetworkCreated = true

	egressNetworkID, err := r.createAndVerifyNetwork(
		ctx,
		plan.EgressNetworkCreateArgs,
		plan.EgressNetworkName,
		false,
		req,
		loaded.Hash,
	)
	if err != nil {
		return nil, err
	}
	resources.egressNetworkCreated = true

	gatewayID, err := r.createContainer(ctx, plan.Gateway.CreateArgs, "egress gateway")
	if err != nil {
		return nil, err
	}
	resources.gatewayContainerID = gatewayID

	if _, stderr, err := r.cli.Run(ctx, plan.GatewayConnectEgressArgs...); err != nil {
		return nil, fmt.Errorf(
			"attach egress gateway to outbound network: %w: %s",
			err,
			strings.TrimSpace(string(stderr)),
		)
	}

	gatewayInspect, err := r.inspect(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	if err := verifyGatewayInspect(req, loaded, route, plan.Gateway, gatewayInspect); err != nil {
		return nil, err
	}

	if _, stderr, err := r.cli.Run(ctx, "start", gatewayID); err != nil {
		return nil, fmt.Errorf("start egress gateway: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	gatewayRunning, err := r.inspect(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	if !gatewayRunning.State.Running {
		return nil, errors.New("egress gateway exited immediately after start")
	}

	workerID, err := r.createContainer(ctx, plan.Worker.CreateArgs, "worker")
	if err != nil {
		return nil, err
	}
	resources.workerContainerID = workerID

	workerInspect, err := r.inspect(ctx, workerID)
	if err != nil {
		return nil, err
	}
	if err := r.verifyInspect(req, plan.Worker, workerInspect); err != nil {
		return nil, err
	}
	if _, stderr, err := r.cli.Run(ctx, "start", workerID); err != nil {
		return nil, fmt.Errorf("start brokered worker: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	workerRunning, err := r.inspect(ctx, workerID)
	if err != nil {
		return nil, err
	}
	if !workerRunning.State.Running {
		return nil, errors.New("brokered worker exited immediately after start")
	}

	r.mu.RLock()
	dockerVer := r.dockerVer
	seccomp := r.seccomp
	cgroups := r.cgroupsV2
	apparmor := r.apparmor
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
		ContainerID:   &workerID,
		StartedAt:     r.cfg.Clock().UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		RequestHash:   spec.BindingHash(req),
		Details: map[string]any{
			"pids_limit":            req.Resources.PIDs,
			"memory_bytes":          req.Resources.MemoryBytes,
			"cpu":                   req.Resources.CPU,
			"egress_network_id":     egressNetworkID,
			"egress_gateway_role":   gatewayRole(route),
			"package_proxy_enabled": false,
		},
		Egress: map[string]any{
			"profile_id":                loaded.Profile.ProfileID,
			"profile_hash":              loaded.Hash,
			"route_id":                  route.RouteID,
			"model":                     *req.Network.Model,
			"gateway_image_digest":      loaded.Profile.GatewayImage.Digest,
			"gateway_container_id":      gatewayID,
			"worker_network_id":         internalNetworkID,
			"gateway_alias":             loaded.Profile.InternalNetwork.GatewayAlias,
			"llm_port":                  attestedGatewayPort(loaded.Profile, route),
			"direct_egress_blocked":     true,
			"provider_secret_in_worker": false,
			"attempt_token_scoped":      !isFreeConnect,
		},
	}
	out.Broker.Kind = "privileged-docker"
	out.Broker.Build = r.cfg.BrokerBuild
	out.Sandbox.ContainerRuntime = "docker-" + dockerVer
	out.Sandbox.UserNamespace = false
	out.Sandbox.Seccomp = seccomp
	out.Sandbox.AppArmor = apparmor
	out.Sandbox.Cgroups = cgroups
	out.Sandbox.NetworkProfile = "brokered"
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
		return nil, fmt.Errorf("marshal brokered sandbox attestation: %w", err)
	}

	success = true
	return payload, nil
}

func gatewayRole(route egressprofile.Route) string {
	if route.Protocol == "opencode-free-connect" {
		return "opencode-free-connect"
	}
	return "llm-provider"
}

func attestedGatewayPort(profile egressprofile.Profile, route egressprofile.Route) int {
	if route.Protocol == "opencode-free-connect" && profile.InternalNetwork.HTTPProxyPort != nil {
		return *profile.InternalNetwork.HTTPProxyPort
	}
	return profile.InternalNetwork.LLMPort
}

func (r *Runtime) createAttemptToken(req spec.Request) (string, string, error) {
	egressDir := filepath.Join(filepath.Clean(req.RunRoot), "egress")
	expected := filepath.Join(filepath.Clean(r.cfg.RunsRoot), req.AttemptID, "egress")
	if egressDir != expected {
		return "", "", errors.New("attempt token directory differs from broker-derived path")
	}
	if err := os.Mkdir(egressDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", "", errors.New("attempt egress token directory already exists")
		}
		return "", "", fmt.Errorf("create attempt egress token directory: %w", err)
	}

	rollback := true
	defer func() {
		if rollback {
			_ = os.RemoveAll(egressDir)
		}
	}()

	if r.cfg.RequireRoot {
		if err := os.Chown(egressDir, 0, int(req.Workspace.ControllerGID)); err != nil {
			return "", "", fmt.Errorf("chown attempt egress token directory: %w", err)
		}
		if err := os.Chmod(egressDir, 0o750); err != nil {
			return "", "", fmt.Errorf("chmod attempt egress token directory: %w", err)
		}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate attempt egress token: %w", err)
	}
	tokenText := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(tokenText, raw)
	for i := range raw {
		raw[i] = 0
	}

	tokenPath := filepath.Join(egressDir, "attempt-token")
	file, err := os.OpenFile(tokenPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		for i := range tokenText {
			tokenText[i] = 0
		}
		return "", "", fmt.Errorf("create attempt egress token: %w", err)
	}
	if _, err := file.Write(tokenText); err != nil {
		_ = file.Close()
		for i := range tokenText {
			tokenText[i] = 0
		}
		return "", "", fmt.Errorf("write attempt egress token: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		for i := range tokenText {
			tokenText[i] = 0
		}
		return "", "", fmt.Errorf("sync attempt egress token: %w", err)
	}
	if err := file.Close(); err != nil {
		for i := range tokenText {
			tokenText[i] = 0
		}
		return "", "", fmt.Errorf("close attempt egress token: %w", err)
	}

	if r.cfg.RequireRoot {
		if err := os.Chown(tokenPath, 0, int(req.Workspace.ControllerGID)); err != nil {
			for i := range tokenText {
				tokenText[i] = 0
			}
			return "", "", fmt.Errorf("chown attempt egress token: %w", err)
		}
		if err := os.Chmod(tokenPath, 0o440); err != nil {
			for i := range tokenText {
				tokenText[i] = 0
			}
			return "", "", fmt.Errorf("chmod attempt egress token: %w", err)
		}
	}

	sum := sha256.Sum256(tokenText)
	hash := hex.EncodeToString(sum[:])
	for i := range tokenText {
		tokenText[i] = 0
	}
	rollback = false
	return tokenPath, hash, nil
}

func (r *Runtime) createAndVerifyNetwork(
	ctx context.Context,
	args []string,
	name string,
	internal bool,
	req spec.Request,
	profileHash string,
) (string, error) {
	stdout, stderr, err := r.cli.Run(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("docker network create failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	cleanup := true
	defer func() {
		if cleanup {
			_, _, _ = r.cli.Run(context.Background(), "network", "rm", name)
		}
	}()

	networkID := strings.TrimSpace(string(stdout))
	if !containerIDPattern.MatchString(networkID) {
		return "", errors.New("docker network create returned invalid network id")
	}
	actual, err := r.inspectNetwork(ctx, name)
	if err != nil {
		return "", err
	}
	if actual.Id != networkID ||
		actual.Name != name ||
		actual.Driver != "bridge" ||
		actual.Internal != internal ||
		actual.Labels["awf.request_id"] != req.RequestID ||
		actual.Labels["awf.attempt_id"] != req.AttemptID ||
		actual.Labels["awf.egress_profile_hash"] != profileHash {
		return "", errors.New("docker network inspect differs from brokered topology policy")
	}
	cleanup = false
	return networkID, nil
}

func (r *Runtime) inspectNetwork(ctx context.Context, name string) (inspectNetwork, error) {
	stdout, stderr, err := r.cli.Run(ctx, "network", "inspect", name)
	if err != nil {
		return inspectNetwork{}, fmt.Errorf("docker network inspect failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	var values []inspectNetwork
	if err := json.Unmarshal(stdout, &values); err != nil {
		return inspectNetwork{}, fmt.Errorf("decode docker network inspect: %w", err)
	}
	if len(values) != 1 {
		return inspectNetwork{}, errors.New("docker network inspect returned unexpected network count")
	}
	return values[0], nil
}

func (r *Runtime) createContainer(ctx context.Context, args []string, role string) (string, error) {
	stdout, stderr, err := r.cli.Run(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("docker create %s failed: %w: %s", role, err, strings.TrimSpace(string(stderr)))
	}
	containerID := strings.TrimSpace(string(stdout))
	if !containerIDPattern.MatchString(containerID) {
		return "", fmt.Errorf("docker create %s returned invalid container id", role)
	}
	return containerID, nil
}

func verifyGatewayInspect(
	req spec.Request,
	loaded egressprofile.Loaded,
	route egressprofile.Route,
	expected egresstopology.GatewaySpec,
	actual inspectContainer,
) error {
	if actual.ID == "" || !containerIDPattern.MatchString(actual.ID) {
		return errors.New("gateway inspect container id is invalid")
	}
	if actual.Config.Image != expected.ExpectedImage {
		return errors.New("gateway image reference differs from pinned spec")
	}
	if actual.Config.User != strconv.Itoa(expected.ProcessUID)+":"+strconv.Itoa(expected.ProcessGID) {
		return errors.New("gateway process identity differs from policy")
	}
	if actual.Config.Labels["awf.role"] != "egress-gateway" ||
		actual.Config.Labels["awf.request_id"] != req.RequestID ||
		actual.Config.Labels["awf.task_id"] != req.TaskID ||
		actual.Config.Labels["awf.attempt_id"] != req.AttemptID ||
		actual.Config.Labels["awf.egress_profile_id"] != loaded.Profile.ProfileID ||
		actual.Config.Labels["awf.egress_profile_hash"] != loaded.Hash ||
		actual.Config.Labels["awf.egress_route_id"] != route.RouteID ||
		actual.Config.Labels["awf.egress_model"] != *req.Network.Model {
		return errors.New("gateway identity labels do not match brokered request")
	}
	if actual.HostConfig.NetworkMode != expected.ExpectedNetworkMode ||
		!actual.HostConfig.ReadonlyRootfs ||
		actual.HostConfig.Privileged {
		return errors.New("gateway network/rootfs/privileged settings do not match policy")
	}
	if !contains(actual.HostConfig.CapDrop, "ALL") ||
		!contains(actual.HostConfig.SecurityOpt, "no-new-privileges:true") {
		return errors.New("gateway capability/no-new-privileges hardening is incomplete")
	}
	if actual.HostConfig.PidsLimit != int64(expected.PIDs) ||
		actual.HostConfig.Memory != expected.MemoryBytes ||
		actual.HostConfig.NanoCPUs != expected.NanoCPUs {
		return errors.New("gateway resource limits differ from policy")
	}
	if len(actual.HostConfig.Devices) != 0 ||
		len(actual.HostConfig.DeviceRequests) != 0 ||
		len(actual.HostConfig.PortBindings) != 0 {
		return errors.New("gateway has forbidden host device or published-port access")
	}
	if _, ok := actual.HostConfig.Tmpfs["/tmp"]; !ok {
		return errors.New("gateway /tmp tmpfs is missing")
	}
	if containsSensitiveEnv(actual.Config.Env) {
		return errors.New("gateway environment contains a secret-like credential")
	}

	if len(actual.Mounts) != len(expected.Mounts) {
		return errors.New("gateway has unexpected mount count")
	}
	for _, mount := range actual.Mounts {
		want := expected.ProviderSecretMount
		if mount.Type != "bind" ||
			mount.Source != want.Source ||
			mount.Destination != want.Destination ||
			mount.RW {
			return errors.New("gateway provider-secret bind mount differs from policy")
		}
	}

	if len(actual.NetworkSettings.Networks) != 2 {
		return errors.New("gateway must have exactly internal and outbound Docker networks")
	}
	internalNetwork, ok := actual.NetworkSettings.Networks[expected.InternalNetworkName]
	if !ok {
		return errors.New("gateway is missing internal worker network")
	}
	if _, ok := actual.NetworkSettings.Networks[expected.EgressNetworkName]; !ok {
		return errors.New("gateway is missing outbound egress network")
	}
	if !contains(internalNetwork.Aliases, loaded.Profile.InternalNetwork.GatewayAlias) {
		return errors.New("gateway internal network alias is missing")
	}
	return nil
}

func (r *Runtime) cleanupBrokeredResources(
	ctx context.Context,
	req spec.Request,
	resources brokeredResources,
) {
	if resources.workerContainerID != "" {
		_, _, _ = r.cli.Run(ctx, "rm", "-f", resources.workerContainerID)
	}
	if resources.gatewayContainerID != "" {
		_, _, _ = r.cli.Run(ctx, "rm", "-f", resources.gatewayContainerID)
	}
	if resources.egressNetworkCreated && resources.egressNetworkName != "" {
		_, _, _ = r.cli.Run(ctx, "network", "rm", resources.egressNetworkName)
	}
	if resources.internalNetworkCreated && resources.internalNetworkName != "" {
		_, _, _ = r.cli.Run(ctx, "network", "rm", resources.internalNetworkName)
	}
	if resources.secretStaged && r.cfg.ProviderSecrets != nil {
		_ = r.cfg.ProviderSecrets.Cleanup(req.AttemptID)
	}
	if resources.tokenCreated {
		_ = os.RemoveAll(filepath.Join(filepath.Clean(req.RunRoot), "egress"))
	}
}

func containsSensitiveEnv(values []string) bool {
	for _, value := range values {
		name, _, _ := strings.Cut(value, "=")
		upper := strings.ToUpper(name)
		if strings.HasSuffix(upper, "_API_KEY") ||
			strings.HasSuffix(upper, "_ACCESS_TOKEN") ||
			strings.HasSuffix(upper, "_AUTH_TOKEN") ||
			strings.HasSuffix(upper, "_SECRET") ||
			strings.HasSuffix(upper, "_PASSWORD") ||
			strings.Contains(upper, "_CREDENTIAL") ||
			upper == "OPENAI_API_KEY" ||
			upper == "ANTHROPIC_API_KEY" ||
			upper == "GITHUB_TOKEN" ||
			upper == "GH_TOKEN" {
			return true
		}
	}
	return false
}

func (r *Runtime) terminateAttempt(
	ctx context.Context,
	req server.TerminateRequest,
) (json.RawMessage, error) {
	if !validTerminationIdentity(req.RequestID) || !validTerminationIdentity(req.AttemptID) {
		return nil, errors.New("invalid request_id or attempt_id")
	}

	workerID, err := r.findSingleContainerByRole(ctx, req, "worker")
	if err != nil {
		return nil, err
	}
	gatewayID, err := r.findSingleContainerByRole(ctx, req, "egress-gateway")
	if err != nil {
		return nil, err
	}
	if workerID != "" && workerID == gatewayID {
		return nil, errors.New("worker and gateway role queries resolved the same container")
	}

	networkIDs, err := r.findAttemptNetworks(ctx, req)
	if err != nil {
		return nil, err
	}

	removedContainers := 0
	for _, id := range []string{workerID, gatewayID} {
		if id == "" {
			continue
		}
		if _, stderr, err := r.cli.Run(ctx, "rm", "-f", id); err != nil {
			return nil, fmt.Errorf("docker rm failed: %w: %s", err, strings.TrimSpace(string(stderr)))
		}
		removedContainers++
	}

	removedNetworks := 0
	for _, id := range networkIDs {
		if _, stderr, err := r.cli.Run(ctx, "network", "rm", id); err != nil {
			return nil, fmt.Errorf("docker network rm failed: %w: %s", err, strings.TrimSpace(string(stderr)))
		}
		removedNetworks++
	}

	if r.cfg.ProviderSecrets != nil {
		if err := r.cfg.ProviderSecrets.Cleanup(req.AttemptID); err != nil {
			return nil, fmt.Errorf("cleanup staged provider secret: %w", err)
		}
	}
	tokenDir := filepath.Join(filepath.Clean(r.cfg.RunsRoot), req.AttemptID, "egress")
	expectedParent := filepath.Join(filepath.Clean(r.cfg.RunsRoot), req.AttemptID)
	if filepath.Dir(tokenDir) != expectedParent {
		return nil, errors.New("attempt token cleanup path escaped run root")
	}
	if err := os.RemoveAll(tokenDir); err != nil {
		return nil, fmt.Errorf("cleanup attempt egress token: %w", err)
	}

	return json.Marshal(map[string]any{
		"status":             "TERMINATED",
		"request_id":         req.RequestID,
		"attempt_id":         req.AttemptID,
		"removed":            removedContainers > 0 || removedNetworks > 0,
		"containers_removed": removedContainers,
		"networks_removed":   removedNetworks,
	})
}

func (r *Runtime) findSingleContainerByRole(
	ctx context.Context,
	req server.TerminateRequest,
	role string,
) (string, error) {
	stdout, stderr, err := r.cli.Run(
		ctx,
		"ps",
		"-aq",
		"--filter", "label=awf.request_id="+req.RequestID,
		"--filter", "label=awf.attempt_id="+req.AttemptID,
		"--filter", "label=awf.role="+role,
	)
	if err != nil {
		return "", fmt.Errorf("docker ps role lookup failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	ids, err := parseDockerIDs(stdout, 1)
	if err != nil {
		return "", fmt.Errorf("%s container lookup: %w", role, err)
	}
	if len(ids) == 0 {
		return "", nil
	}
	return ids[0], nil
}

func (r *Runtime) findAttemptNetworks(
	ctx context.Context,
	req server.TerminateRequest,
) ([]string, error) {
	stdout, stderr, err := r.cli.Run(
		ctx,
		"network",
		"ls",
		"-q",
		"--filter", "label=awf.request_id="+req.RequestID,
		"--filter", "label=awf.attempt_id="+req.AttemptID,
	)
	if err != nil {
		return nil, fmt.Errorf("docker network lookup failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	ids, err := parseDockerIDs(stdout, 2)
	if err != nil {
		return nil, fmt.Errorf("attempt network lookup: %w", err)
	}
	return ids, nil
}

func parseDockerIDs(stdout []byte, max int) ([]string, error) {
	var ids []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		if !containerIDPattern.MatchString(id) {
			return nil, errors.New("Docker lookup returned invalid object id")
		}
		if _, exists := seen[id]; exists {
			return nil, errors.New("Docker lookup returned duplicate object id")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) > max {
		return nil, errors.New("Docker lookup returned an ambiguous object set")
	}
	return ids, nil
}

func validTerminationIdentity(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == ':' || c == '-' {
			continue
		}
		return false
	}
	return true
}

const statusLogTailBytes = 64 * 1024

func (r *Runtime) Status(
	ctx context.Context,
	req server.AttemptStatusRequest,
) (json.RawMessage, error) {
	if !r.Ready() {
		return nil, server.ErrUnavailable
	}
	if !validTerminationIdentity(req.RequestID) || !validTerminationIdentity(req.AttemptID) {
		return nil, errors.New("invalid request_id or attempt_id")
	}

	lookup := server.TerminateRequest{
		RequestID: req.RequestID,
		AttemptID: req.AttemptID,
	}
	workerID, err := r.findSingleContainerByRole(ctx, lookup, "worker")
	if err != nil {
		return nil, err
	}
	if workerID == "" {
		return json.Marshal(map[string]any{
			"schema_version": "1.0",
			"request_id":     req.RequestID,
			"attempt_id":     req.AttemptID,
			"state":          "NOT_FOUND",
			"running":        false,
			"exit_code":      nil,
			"container_id":   nil,
			"stdout_tail":    "",
			"stderr_tail":    "",
			"logs_available": false,
			"observed_at":    r.cfg.Clock().UTC().Format(time.RFC3339Nano),
		})
	}

	actual, err := r.inspect(ctx, workerID)
	if err != nil {
		return nil, err
	}
	if actual.Config.Labels["awf.role"] != "worker" ||
		actual.Config.Labels["awf.request_id"] != req.RequestID ||
		actual.Config.Labels["awf.attempt_id"] != req.AttemptID {
		return nil, errors.New("worker status inspect labels do not match request")
	}

	state := "EXITED"
	var exitCode any = actual.State.ExitCode
	if actual.State.Running {
		state = "RUNNING"
		exitCode = nil
	}

	stdoutTail := ""
	stderrTail := ""
	logsAvailable := false
	stdout, stderr, logErr := r.cli.Run(ctx, "logs", "--tail", "200", workerID)
	if logErr == nil {
		stdoutTail = boundedTail(stdout, statusLogTailBytes)
		stderrTail = boundedTail(stderr, statusLogTailBytes)
		logsAvailable = true
	}

	return json.Marshal(map[string]any{
		"schema_version": "1.0",
		"request_id":     req.RequestID,
		"attempt_id":     req.AttemptID,
		"state":          state,
		"running":        actual.State.Running,
		"exit_code":      exitCode,
		"container_id":   workerID,
		"stdout_tail":    stdoutTail,
		"stderr_tail":    stderrTail,
		"logs_available": logsAvailable,
		"observed_at":    r.cfg.Clock().UTC().Format(time.RFC3339Nano),
	})
}

func boundedTail(value []byte, max int) string {
	if max <= 0 || len(value) == 0 {
		return ""
	}
	if len(value) <= max {
		return string(value)
	}
	return string(value[len(value)-max:])
}
