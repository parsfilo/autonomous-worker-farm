package egresstopology

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"autonomous-worker/broker/internal/egressprofile"
	"autonomous-worker/broker/internal/spec"
)

const (
	gatewayUID            = 65532
	gatewayGID            = 65532
	gatewayMemoryBytes    = 256 << 20
	gatewayPIDs           = 128
	gatewayCPU            = "0.5"
	gatewaySecretFile     = "/run/secrets/provider"
	attemptTokenContainer = "/run/egress/attempt-token"
)

var lowercaseHashPattern = regexp.MustCompile("^[0-9a-f]{64}$")

type GatewaySpec struct {
	ContainerName       string
	CreateArgs          []string
	ExpectedImage       string
	ExpectedNetworkMode string
	InternalNetworkName string
	EgressNetworkName   string
	ProcessUID          int
	ProcessGID          int
	PIDs                int
	MemoryBytes         int64
	NanoCPUs            int64
	Mounts              []spec.Mount
	ProviderSecretMount spec.Mount
}

type Plan struct {
	InternalNetworkName       string
	EgressNetworkName         string
	InternalNetworkCreateArgs []string
	EgressNetworkCreateArgs   []string
	Gateway                   GatewaySpec
	GatewayConnectEgressArgs  []string
	Worker                    spec.DockerSpec
	AttemptTokenPath          string
}

type CompileInput struct {
	Request            spec.Request
	LoadedProfile      egressprofile.Loaded
	RunsRoot           string
	ProviderSecretPath string
	AttemptTokenPath   string
	AttemptTokenSHA256 string
	Now                time.Time
	Limits             spec.Limits
}

func Compile(input CompileInput) (Plan, error) {
	req := input.Request
	if req.Network.Profile != "brokered" {
		return Plan{}, errors.New("egress topology requires network:brokered")
	}
	if err := spec.ValidateRequest(req, input.RunsRoot, input.Now, input.Limits); err != nil {
		return Plan{}, err
	}
	if req.Network.EgressProfileID == nil ||
		req.Network.EgressProfileHash == nil ||
		req.Network.RouteID == nil ||
		req.Network.Model == nil {
		return Plan{}, errors.New("brokered network binding is incomplete")
	}

	loaded := input.LoadedProfile
	if loaded.Profile.ProfileID != *req.Network.EgressProfileID {
		return Plan{}, errors.New("egress profile id binding mismatch")
	}
	if loaded.Hash != *req.Network.EgressProfileHash {
		return Plan{}, errors.New("egress profile hash binding mismatch")
	}
	route, err := loaded.Resolve(*req.Network.RouteID, *req.Network.Model)
	if err != nil {
		return Plan{}, err
	}
	isFreeConnect := route.Protocol == "opencode-free-connect"

	expectedAttemptTokenPath := ""
	if isFreeConnect {
		if input.ProviderSecretPath != "" ||
			input.AttemptTokenPath != "" ||
			input.AttemptTokenSHA256 != "" {
			return Plan{}, errors.New("opencode-free-connect must not receive provider secret or attempt token material")
		}
	} else {
		expectedAttemptTokenPath = filepath.Join(filepath.Clean(req.RunRoot), "egress", "attempt-token")
		if filepath.Clean(input.AttemptTokenPath) != expectedAttemptTokenPath {
			return Plan{}, errors.New("attempt token path must be derived from run_root")
		}
		if !safeDockerBindSource(input.AttemptTokenPath) {
			return Plan{}, errors.New("invalid attempt token bind source")
		}
		if !lowercaseHashPattern.MatchString(input.AttemptTokenSHA256) {
			return Plan{}, errors.New("invalid attempt token SHA-256")
		}
		runsRoot := filepath.Clean(input.RunsRoot)
		providerSecretPath := filepath.Clean(input.ProviderSecretPath)
		if !safeDockerBindSource(providerSecretPath) || providerSecretPath == runsRoot ||
			under(runsRoot, providerSecretPath) {
			return Plan{}, errors.New("provider secret must live outside the broker runs root")
		}
	}

	identityHash := sha256.Sum256([]byte(req.RequestID + "\x00" + req.AttemptID))
	suffix := hex.EncodeToString(identityHash[:6])
	internalNetwork := "awf-int-" + suffix
	egressNetwork := "awf-eg-" + suffix
	gatewayName := "awf-gw-" + suffix

	worker, err := spec.BuildBrokeredWorkerDockerSpec(
		req,
		input.RunsRoot,
		input.Now,
		input.Limits,
		internalNetwork,
	)
	if err != nil {
		return Plan{}, err
	}

	gatewayImage, err := pinnedImage(
		loaded.Profile.GatewayImage.Reference,
		loaded.Profile.GatewayImage.Digest,
	)
	if err != nil {
		return Plan{}, err
	}

	if isFreeConnect {
		proxyPort := loaded.Profile.InternalNetwork.HTTPProxyPort
		if proxyPort == nil {
			return Plan{}, errors.New("opencode-free-connect is missing http_proxy_port")
		}
		proxyURL := "http://" + loaded.Profile.InternalNetwork.GatewayAlias + ":" + strconv.Itoa(*proxyPort)
		worker.CreateArgs, err = addDockerEnvBeforeImage(
			worker.CreateArgs,
			worker.ExpectedImage,
			[]string{
				"HTTPS_PROXY=" + proxyURL,
				"https_proxy=" + proxyURL,
				"HTTP_PROXY=" + proxyURL,
				"http_proxy=" + proxyURL,
				"NO_PROXY=127.0.0.1,localhost,::1",
				"no_proxy=127.0.0.1,localhost,::1",
			},
		)
		if err != nil {
			return Plan{}, err
		}
	}

	labels := []string{
		"awf.role=egress-gateway",
		"awf.request_id=" + req.RequestID,
		"awf.task_id=" + req.TaskID,
		"awf.attempt_id=" + req.AttemptID,
		"awf.egress_profile_id=" + loaded.Profile.ProfileID,
		"awf.egress_profile_hash=" + loaded.Hash,
		"awf.egress_route_id=" + route.RouteID,
		"awf.egress_model=" + *req.Network.Model,
	}
	networkLabels := []string{
		"awf.request_id=" + req.RequestID,
		"awf.attempt_id=" + req.AttemptID,
		"awf.egress_profile_hash=" + loaded.Hash,
	}

	internalCreate := []string{"network", "create", "--driver", "bridge", "--internal"}
	for _, label := range networkLabels {
		internalCreate = append(internalCreate, "--label", label)
	}
	internalCreate = append(internalCreate, internalNetwork)

	egressCreate := []string{"network", "create", "--driver", "bridge"}
	for _, label := range networkLabels {
		egressCreate = append(egressCreate, "--label", label)
	}
	egressCreate = append(egressCreate, egressNetwork)

	gatewayArgs := []string{
		"create",
		"--name", gatewayName,
	}
	for _, label := range labels {
		gatewayArgs = append(gatewayArgs, "--label", label)
	}
	gatewayArgs = append(gatewayArgs,
		"--network", internalNetwork,
		"--network-alias", loaded.Profile.InternalNetwork.GatewayAlias,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", strconv.Itoa(gatewayPIDs),
		"--memory", strconv.Itoa(gatewayMemoryBytes),
		"--cpus", gatewayCPU,
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
		"--user", strconv.Itoa(gatewayUID)+":"+strconv.Itoa(gatewayGID),
	)

	mounts := []spec.Mount{}
	secretMount := spec.Mount{}
	if isFreeConnect {
		proxyPort := *loaded.Profile.InternalNetwork.HTTPProxyPort
		gatewayArgs = append(gatewayArgs,
			gatewayImage,
			"--mode", "opencode-free-connect",
			"--listen", ":"+strconv.Itoa(proxyPort),
			"--proxy-host", "opencode.ai",
			"--proxy-port", "443",
			"--max-concurrent-requests", strconv.Itoa(loaded.Profile.Limits.MaxConcurrentRequests),
		)
	} else {
		secretMount = spec.Mount{
			Source:      filepath.Clean(input.ProviderSecretPath),
			Destination: gatewaySecretFile,
			ReadOnly:    true,
		}
		mounts = append(mounts, secretMount)
		gatewayArgs = append(gatewayArgs,
			"--mount", dockerMountArg(secretMount),
			gatewayImage,
			"--mode", "provider",
			"--listen", ":"+strconv.Itoa(loaded.Profile.InternalNetwork.LLMPort),
			"--route-id", route.RouteID,
			"--protocol", route.Protocol,
			"--upstream-base-url", route.UpstreamBaseURL,
			"--worker-auth-kind", route.WorkerAuth.Kind,
			"--worker-auth-header", route.WorkerAuth.HeaderName,
			"--attempt-token-sha256", input.AttemptTokenSHA256,
			"--upstream-auth-kind", route.UpstreamAuth.Kind,
			"--upstream-auth-header", route.UpstreamAuth.HeaderName,
			"--provider-secret-file", gatewaySecretFile,
			"--max-request-bytes", strconv.FormatInt(loaded.Profile.Limits.MaxRequestBytes, 10),
			"--max-response-bytes", strconv.FormatInt(loaded.Profile.Limits.MaxResponseBytes, 10),
			"--max-concurrent-requests", strconv.Itoa(loaded.Profile.Limits.MaxConcurrentRequests),
			"--allowed-model", *req.Network.Model,
		)
		for _, prefix := range route.RequestPathPrefixes {
			gatewayArgs = append(gatewayArgs, "--path-prefix", prefix)
		}
	}

	return Plan{
		InternalNetworkName:       internalNetwork,
		EgressNetworkName:         egressNetwork,
		InternalNetworkCreateArgs: internalCreate,
		EgressNetworkCreateArgs:   egressCreate,
		Gateway: GatewaySpec{
			ContainerName:       gatewayName,
			CreateArgs:          gatewayArgs,
			ExpectedImage:       gatewayImage,
			ExpectedNetworkMode: internalNetwork,
			InternalNetworkName: internalNetwork,
			EgressNetworkName:   egressNetwork,
			ProcessUID:          gatewayUID,
			ProcessGID:          gatewayGID,
			PIDs:                gatewayPIDs,
			MemoryBytes:         gatewayMemoryBytes,
			NanoCPUs:            500_000_000,
			Mounts:              mounts,
			ProviderSecretMount: secretMount,
		},
		GatewayConnectEgressArgs: []string{
			"network", "connect", egressNetwork, gatewayName,
		},
		Worker:           worker,
		AttemptTokenPath: expectedAttemptTokenPath,
	}, nil
}

func addDockerEnvBeforeImage(args []string, image string, values []string) ([]string, error) {
	index := -1
	for i, value := range args {
		if value == image {
			if index != -1 {
				return nil, errors.New("worker Docker argv contains duplicate image boundary")
			}
			index = i
		}
	}
	if index == -1 {
		return nil, errors.New("worker Docker argv is missing expected image boundary")
	}
	result := make([]string, 0, len(args)+len(values)*2)
	result = append(result, args[:index]...)
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return nil, errors.New("invalid worker proxy environment")
		}
		result = append(result, "--env", value)
	}
	result = append(result, args[index:]...)
	return result, nil
}

func dockerMountArg(m spec.Mount) string {
	value := "type=bind,src=" + m.Source + ",dst=" + m.Destination
	if m.ReadOnly {
		value += ",readonly"
	}
	return value
}

func pinnedImage(reference, digest string) (string, error) {
	if reference == "" || strings.ContainsAny(reference, " \t\r\n") ||
		!regexp.MustCompile("^sha256:[0-9a-f]{64}$").MatchString(digest) {
		return "", errors.New("invalid pinned gateway image")
	}
	if strings.Contains(reference, "@") {
		parts := strings.SplitN(reference, "@", 2)
		if parts[0] == "" || parts[1] != digest {
			return "", errors.New("gateway image reference digest mismatch")
		}
		return reference, nil
	}
	return reference + "@" + digest, nil
}

func safeDockerBindSource(value string) bool {
	return filepath.IsAbs(value) &&
		filepath.Clean(value) == value &&
		!strings.ContainsAny(value, ",\x00\r\n")
}

func under(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}
