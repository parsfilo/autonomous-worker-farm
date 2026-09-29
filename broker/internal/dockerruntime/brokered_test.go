package dockerruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"autonomous-worker/broker/internal/egressprofile"
	"autonomous-worker/broker/internal/server"
	"autonomous-worker/broker/internal/spec"
)

type staticProfileStore struct {
	loaded egressprofile.Loaded
}

func (s staticProfileStore) Load(profileID string) (egressprofile.Loaded, error) {
	if profileID != s.loaded.Profile.ProfileID {
		return egressprofile.Loaded{}, errors.New("profile not found")
	}
	return s.loaded, nil
}

type trackingSecretStore struct {
	path    string
	staged  bool
	cleaned bool
}

func (s *trackingSecretStore) Stage(secretHandle, attemptID string) (string, error) {
	if secretHandle != "secret://providers/openai-main" || attemptID == "" {
		return "", errors.New("unexpected secret staging request")
	}
	s.staged = true
	return s.path, nil
}

func (s *trackingSecretStore) Cleanup(attemptID string) error {
	if attemptID == "" {
		return errors.New("missing cleanup attempt id")
	}
	s.cleaned = true
	return nil
}

type fakeNetwork struct {
	id       string
	name     string
	internal bool
	labels   map[string]string
}

type brokeredDockerState struct {
	networks            map[string]fakeNetwork
	gatewayCreate       []string
	workerCreate        []string
	gatewayConnected    bool
	gatewayStarted      bool
	workerStarted       bool
	failWorkerStart     bool
	networkInspectDrift bool
}

func loadTestEgressProfile(t *testing.T) egressprofile.Loaded {
	t.Helper()
	data, err := os.ReadFile("../../../examples/egress-profile.example.json")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := egressprofile.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return egressprofile.Loaded{
		Profile: profile,
		Hash:    egressprofile.BindingHash(profile),
		Path:    "/etc/autonomous-worker/egress-profiles/llm-default.json",
	}
}

func brokeredRequest(t *testing.T, runsRoot string, loaded egressprofile.Loaded) spec.Request {
	t.Helper()
	req := testRequest()
	req.RunRoot = filepath.Join(runsRoot, req.AttemptID)
	req.Workspace.Source = filepath.Join(req.RunRoot, "repo")
	for _, dir := range []string{
		req.RunRoot,
		filepath.Join(req.RunRoot, "repo"),
		filepath.Join(req.RunRoot, "control"),
		filepath.Join(req.RunRoot, "artifacts"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	profileID := loaded.Profile.ProfileID
	profileHash := loaded.Hash
	routeID := "openai-responses"
	model := "gpt-5.2"
	req.Network.Profile = "brokered"
	req.Network.EgressProfileID = &profileID
	req.Network.EgressProfileHash = &profileHash
	req.Network.RouteID = &routeID
	req.Network.Model = &model
	return req
}

func newBrokeredRuntime(
	t *testing.T,
	runsRoot string,
	loaded egressprofile.Loaded,
	secrets ProviderSecretStore,
	cli CLI,
) *Runtime {
	t.Helper()
	runtime, err := New(Config{
		RunsRoot:        runsRoot,
		BrokerBuild:     "broker-build-001",
		MachineID:       "production-vps",
		RequireRoot:     false,
		Clock:           testClock,
		EgressProfiles:  staticProfileStore{loaded: loaded},
		ProviderSecrets: secrets,
	}, cli)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func brokeredCLI(t *testing.T, req spec.Request, loaded egressprofile.Loaded, state *brokeredDockerState) *fakeCLI {
	t.Helper()
	if state.networks == nil {
		state.networks = map[string]fakeNetwork{}
	}
	gatewayID := strings.Repeat("3", 64)
	workerID := strings.Repeat("4", 64)
	nextNetworkDigit := byte('5')

	return &fakeCLI{run: func(args []string) ([]byte, []byte, error) {
		if len(args) == 0 {
			return nil, nil, errors.New("empty docker command")
		}
		switch args[0] {
		case "info":
			return dockerInfoJSON(true), nil, nil
		case "image":
			if len(args) < 3 || args[1] != "inspect" {
				return nil, nil, errors.New("unexpected image command")
			}
			imageRef := args[2]
			payload, _ := json.Marshal([]string{imageRef})
			return payload, nil, nil
		case "network":
			if len(args) < 2 {
				return nil, nil, errors.New("short network command")
			}
			switch args[1] {
			case "create":
				name := args[len(args)-1]
				id := strings.Repeat(string(nextNetworkDigit), 64)
				nextNetworkDigit++
				state.networks[name] = fakeNetwork{
					id:       id,
					name:     name,
					internal: hasArg(args, "--internal"),
					labels:   flagMap(args, "--label"),
				}
				return []byte(id + "\n"), nil, nil
			case "inspect":
				network, ok := state.networks[args[2]]
				if !ok {
					return nil, nil, errors.New("network not found")
				}
				internal := network.internal
				if state.networkInspectDrift {
					internal = !internal
				}
				payload, _ := json.Marshal([]map[string]any{{
					"Name":     network.name,
					"Id":       network.id,
					"Driver":   "bridge",
					"Internal": internal,
					"Labels":   network.labels,
				}})
				return payload, nil, nil
			case "connect":
				state.gatewayConnected = true
				return nil, nil, nil
			case "rm":
				delete(state.networks, args[2])
				return []byte(args[2] + "\n"), nil, nil
			default:
				return nil, nil, errors.New("unexpected network command")
			}
		case "create":
			labels := flagMap(args, "--label")
			if labels["awf.role"] == "egress-gateway" {
				state.gatewayCreate = append([]string(nil), args...)
				return []byte(gatewayID + "\n"), nil, nil
			}
			if labels["awf.role"] == "worker" {
				state.workerCreate = append([]string(nil), args...)
				return []byte(workerID + "\n"), nil, nil
			}
			return nil, nil, errors.New("unknown container role")
		case "inspect":
			if len(args) != 2 {
				return nil, nil, errors.New("unexpected inspect argv")
			}
			switch args[1] {
			case gatewayID:
				return containerInspectFromCreate(
					t,
					gatewayID,
					state.gatewayCreate,
					state.gatewayStarted,
					state.gatewayConnected,
					"",
				), nil, nil
			case workerID:
				return containerInspectFromCreate(
					t,
					workerID,
					state.workerCreate,
					state.workerStarted,
					false,
					"",
				), nil, nil
			default:
				return nil, nil, errors.New("unknown inspect container")
			}
		case "start":
			if args[1] == gatewayID {
				state.gatewayStarted = true
				return []byte(gatewayID + "\n"), nil, nil
			}
			if args[1] == workerID {
				if state.failWorkerStart {
					return nil, []byte("simulated worker start failure"), errors.New("start failed")
				}
				state.workerStarted = true
				return []byte(workerID + "\n"), nil, nil
			}
			return nil, nil, errors.New("unexpected start target")
		case "rm":
			return []byte(args[len(args)-1] + "\n"), nil, nil
		default:
			return nil, nil, errors.New("unexpected docker command: " + strings.Join(args, " "))
		}
	}}
}

func containerInspectFromCreate(
	t *testing.T,
	id string,
	createArgs []string,
	running bool,
	gatewayConnected bool,
	envInjection string,
) []byte {
	t.Helper()
	if len(createArgs) == 0 {
		t.Fatal("container inspect requested before create")
	}
	labels := flagMap(createArgs, "--label")
	networkMode := flagValue(createArgs, "--network")
	aliases := flagValues(createArgs, "--network-alias")
	networks := map[string]any{}
	if networkMode != "" && networkMode != "none" {
		networks[networkMode] = map[string]any{"Aliases": aliases}
	}
	if gatewayConnected {
		var outbound string
		for _, arg := range createArgs {
			if strings.HasPrefix(arg, "awf-eg-") {
				outbound = arg
			}
		}
		if outbound == "" {
			// The outbound network is connected after create, so infer it from the deterministic sibling name.
			if strings.HasPrefix(networkMode, "awf-int-") {
				outbound = strings.Replace(networkMode, "awf-int-", "awf-eg-", 1)
			}
		}
		networks[outbound] = map[string]any{"Aliases": []string{}}
	}

	mounts := []map[string]any{}
	for _, value := range flagValues(createArgs, "--mount") {
		parts := strings.Split(value, ",")
		fields := map[string]string{}
		readOnly := false
		for _, part := range parts {
			if part == "readonly" {
				readOnly = true
				continue
			}
			key, val, ok := strings.Cut(part, "=")
			if ok {
				fields[key] = val
			}
		}
		mounts = append(mounts, map[string]any{
			"Type":        fields["type"],
			"Source":      fields["src"],
			"Destination": fields["dst"],
			"RW":          !readOnly,
		})
	}

	tmpfs := map[string]string{}
	for _, value := range flagValues(createArgs, "--tmpfs") {
		dest, opts, _ := strings.Cut(value, ":")
		tmpfs[dest] = opts
	}
	env := flagValues(createArgs, "--env")
	if envInjection != "" {
		env = append(env, envInjection)
	}
	pids, _ := strconv.ParseInt(flagValue(createArgs, "--pids-limit"), 10, 64)
	memory, _ := strconv.ParseInt(flagValue(createArgs, "--memory"), 10, 64)
	cpu, _ := strconv.ParseFloat(flagValue(createArgs, "--cpus"), 64)
	image := ""
	for _, arg := range createArgs {
		if strings.Contains(arg, "@sha256:") {
			image = arg
			break
		}
	}

	value := map[string]any{
		"Id":    id,
		"Image": "sha256:" + strings.Repeat("9", 64),
		"Config": map[string]any{
			"Image":  image,
			"User":   flagValue(createArgs, "--user"),
			"Labels": labels,
			"Env":    env,
		},
		"HostConfig": map[string]any{
			"NetworkMode":    networkMode,
			"ReadonlyRootfs": hasArg(createArgs, "--read-only"),
			"Privileged":     false,
			"CapDrop":        flagValues(createArgs, "--cap-drop"),
			"SecurityOpt":    flagValues(createArgs, "--security-opt"),
			"PidsLimit":      pids,
			"Memory":         memory,
			"NanoCpus":       int64(cpu * 1_000_000_000),
			"Tmpfs":          tmpfs,
			"Devices":        []any{},
			"DeviceRequests": []any{},
			"PortBindings":   map[string]any{},
		},
		"NetworkSettings": map[string]any{
			"Networks": networks,
		},
		"Mounts": mounts,
		"State": map[string]any{
			"Running":  running,
			"ExitCode": 0,
		},
	}
	payload, err := json.Marshal([]any{value})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func flagValue(args []string, flag string) string {
	values := flagValues(args, flag)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func flagValues(args []string, flag string) []string {
	var values []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			values = append(values, args[i+1])
			i++
		}
	}
	return values
}

func flagMap(args []string, flag string) map[string]string {
	values := map[string]string{}
	for _, item := range flagValues(args, flag) {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[key] = value
		}
	}
	return values
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func TestBrokeredProvisionBuildsGatewayTopologyAndBoundAttestation(t *testing.T) {
	runsRoot := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(runsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := loadTestEgressProfile(t)
	req := brokeredRequest(t, runsRoot, loaded)

	secretDir := t.TempDir()
	secretPath := filepath.Join(secretDir, "provider-secret")
	if err := os.WriteFile(secretPath, []byte("provider-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets := &trackingSecretStore{path: secretPath}
	state := &brokeredDockerState{}
	cli := brokeredCLI(t, req, loaded, state)
	runtime := newBrokeredRuntime(t, runsRoot, loaded, secrets, cli)

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
	sandbox := att["sandbox"].(map[string]any)
	if sandbox["network_profile"] != "brokered" || sandbox["network_enforced"] != true {
		t.Fatalf("unexpected brokered network attestation: %v", sandbox)
	}
	egress := att["egress"].(map[string]any)
	if egress["profile_hash"] != loaded.Hash ||
		egress["route_id"] != "openai-responses" ||
		egress["model"] != "gpt-5.2" ||
		egress["provider_secret_in_worker"] != false ||
		egress["direct_egress_blocked"] != true {
		t.Fatalf("unexpected egress attestation: %v", egress)
	}

	if !secrets.staged || secrets.cleaned {
		t.Fatalf("provider secret lifecycle incorrect after successful provision: staged=%v cleaned=%v", secrets.staged, secrets.cleaned)
	}
	if len(state.networks) != 2 || !state.gatewayConnected || !state.gatewayStarted || !state.workerStarted {
		t.Fatalf("brokered topology did not fully start: %+v", state)
	}

	workerArgs := strings.Join(state.workerCreate, " ")
	if strings.Contains(workerArgs, secretPath) {
		t.Fatal("provider secret path leaked into worker create argv")
	}
	gatewayArgs := strings.Join(state.gatewayCreate, " ")
	if !strings.Contains(gatewayArgs, secretPath) {
		t.Fatal("gateway did not receive provider secret mount path")
	}

	tokenPath := filepath.Join(req.RunRoot, "egress", "attempt-token")
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(token)
	expectedHash := hex.EncodeToString(sum[:])
	if !strings.Contains(gatewayArgs, "--attempt-token-sha256 "+expectedHash) {
		t.Fatal("gateway argv is not bound to the generated attempt token hash")
	}
	if strings.Contains(gatewayArgs, string(token)) {
		t.Fatal("raw attempt token leaked into gateway argv")
	}
}

func TestBrokeredProvisionRollsBackAllResourcesOnWorkerStartFailure(t *testing.T) {
	runsRoot := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(runsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := loadTestEgressProfile(t)
	req := brokeredRequest(t, runsRoot, loaded)

	secretPath := filepath.Join(t.TempDir(), "provider-secret")
	if err := os.WriteFile(secretPath, []byte("provider-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets := &trackingSecretStore{path: secretPath}
	state := &brokeredDockerState{failWorkerStart: true}
	cli := brokeredCLI(t, req, loaded, state)
	runtime := newBrokeredRuntime(t, runsRoot, loaded, secrets, cli)
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := runtime.Provision(context.Background(), req); err == nil {
		t.Fatal("expected simulated worker start failure")
	}
	if !secrets.cleaned {
		t.Fatal("staged provider secret was not cleaned up after provision failure")
	}
	if _, err := os.Lstat(filepath.Join(req.RunRoot, "egress")); !os.IsNotExist(err) {
		t.Fatalf("attempt token directory survived failed provision: %v", err)
	}
	if len(state.networks) != 0 {
		t.Fatalf("Docker networks survived failed provision: %+v", state.networks)
	}

	var removedGateway, removedWorker bool
	for _, call := range cli.calls {
		if len(call) == 3 && call[0] == "rm" && call[1] == "-f" {
			if call[2] == strings.Repeat("3", 64) {
				removedGateway = true
			}
			if call[2] == strings.Repeat("4", 64) {
				removedWorker = true
			}
		}
	}
	if !removedGateway || !removedWorker {
		t.Fatalf("container rollback incomplete: gateway=%v worker=%v", removedGateway, removedWorker)
	}
}

func TestWorkerInspectRejectsSecretLikeEnvironment(t *testing.T) {
	req := testRequest()
	specification, err := spec.BuildDockerSpec(req, testRunsRoot, testClock(), spec.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	actualBytes := inspectJSON(t, req, func(value map[string]any) {
		config := value["Config"].(map[string]any)
		config["Env"] = []string{"OPENAI_API_KEY=must-not-exist"}
	})
	var values []inspectContainer
	if err := json.Unmarshal(actualBytes, &values); err != nil {
		t.Fatal(err)
	}
	runtime := newRuntime(t, provisionCLI(t, req, nil))
	if err := runtime.verifyInspect(req, specification, values[0]); err == nil {
		t.Fatal("expected worker secret-like environment to be rejected")
	}
}

func TestBrokeredProvisionStillFailsClosedWithoutStores(t *testing.T) {
	req := testRequest()
	profileID := "llm-default"
	profileHash := strings.Repeat("e", 64)
	routeID := "openai-responses"
	model := "gpt-5.2"
	req.Network.Profile = "brokered"
	req.Network.EgressProfileID = &profileID
	req.Network.EgressProfileHash = &profileHash
	req.Network.RouteID = &routeID
	req.Network.Model = &model

	runtime := newRuntime(t, provisionCLI(t, req, nil))
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Provision(context.Background(), req); !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("expected unavailable brokered runtime without stores, got %v", err)
	}
}

func TestTerminateCleansBrokeredContainersNetworksSecretsAndToken(t *testing.T) {
	runsRoot := filepath.Join(t.TempDir(), "runs")
	attemptID := "attempt-001"
	tokenDir := filepath.Join(runsRoot, attemptID, "egress")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenDir, "attempt-token"), []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}

	workerID := strings.Repeat("7", 64)
	gatewayID := strings.Repeat("8", 64)
	networkID1 := strings.Repeat("a", 64)
	networkID2 := strings.Repeat("b", 64)
	removed := map[string]bool{}
	secrets := &trackingSecretStore{path: filepath.Join(t.TempDir(), "provider-secret")}

	cli := &fakeCLI{run: func(args []string) ([]byte, []byte, error) {
		switch args[0] {
		case "info":
			return dockerInfoJSON(true), nil, nil
		case "ps":
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "label=awf.role=worker") {
				return []byte(workerID + "\n"), nil, nil
			}
			if strings.Contains(joined, "label=awf.role=egress-gateway") {
				return []byte(gatewayID + "\n"), nil, nil
			}
			return nil, nil, errors.New("missing terminate role filter")
		case "rm":
			if len(args) != 3 || args[1] != "-f" {
				return nil, nil, errors.New("unexpected container rm")
			}
			removed[args[2]] = true
			return []byte(args[2] + "\n"), nil, nil
		case "network":
			if len(args) >= 2 && args[1] == "ls" {
				return []byte(networkID1 + "\n" + networkID2 + "\n"), nil, nil
			}
			if len(args) == 3 && args[1] == "rm" {
				removed[args[2]] = true
				return []byte(args[2] + "\n"), nil, nil
			}
			return nil, nil, errors.New("unexpected terminate network command")
		default:
			return nil, nil, errors.New("unexpected terminate command")
		}
	}}

	runtime, err := New(Config{
		RunsRoot:        runsRoot,
		BrokerBuild:     "broker-build-001",
		MachineID:       "production-vps",
		RequireRoot:     false,
		Clock:           testClock,
		ProviderSecrets: secrets,
	}, cli)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}

	payload, err := runtime.Terminate(context.Background(), server.TerminateRequest{
		RequestID: "req-001",
		AttemptID: attemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result["containers_removed"] != float64(2) || result["networks_removed"] != float64(2) {
		t.Fatalf("unexpected brokered termination result: %v", result)
	}
	for _, id := range []string{workerID, gatewayID, networkID1, networkID2} {
		if !removed[id] {
			t.Fatalf("resource %s was not removed", id)
		}
	}
	if !secrets.cleaned {
		t.Fatal("staged provider secret runtime was not cleaned")
	}
	if _, err := os.Lstat(tokenDir); !os.IsNotExist(err) {
		t.Fatalf("attempt token directory survived terminate: %v", err)
	}
}

func TestBrokeredNetworkInspectDriftRollsBackCreatedNetwork(t *testing.T) {
	runsRoot := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(runsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := loadTestEgressProfile(t)
	req := brokeredRequest(t, runsRoot, loaded)
	secretPath := filepath.Join(t.TempDir(), "provider-secret")
	if err := os.WriteFile(secretPath, []byte("provider-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets := &trackingSecretStore{path: secretPath}
	state := &brokeredDockerState{networkInspectDrift: true}
	cli := brokeredCLI(t, req, loaded, state)
	runtime := newBrokeredRuntime(t, runsRoot, loaded, secrets, cli)
	if err := runtime.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := runtime.Provision(context.Background(), req); err == nil {
		t.Fatal("expected network inspect drift to reject brokered provision")
	}
	if len(state.networks) != 0 {
		t.Fatalf("network created before inspect failure was not rolled back: %+v", state.networks)
	}
	if !secrets.cleaned {
		t.Fatal("provider secret staging was not rolled back after network inspect failure")
	}
}

func loadTestFreeEgressProfile(t *testing.T) egressprofile.Loaded {
	t.Helper()
	loaded := loadTestEgressProfile(t)
	port := 8888
	loaded.Profile.InternalNetwork.HTTPProxyPort = &port
	loaded.Profile.Routes = []egressprofile.Route{
		{
			RouteID:         "opencode-free",
			ProviderID:      "opencode",
			Protocol:        "opencode-free-connect",
			UpstreamBaseURL: "https://opencode.ai",
			WorkerBasePath:  "/",
			WorkerAuth: egressprofile.WorkerAuth{
				Kind:       "none",
				HeaderName: "",
				SecretFile: nil,
			},
			UpstreamAuth: egressprofile.Auth{
				Kind:       "none",
				HeaderName: "",
			},
			SecretHandle:        nil,
			Models:              []string{"opencode/*"},
			RequestPathPrefixes: []string{},
		},
	}
	if err := egressprofile.Validate(loaded.Profile); err != nil {
		t.Fatal(err)
	}
	loaded.Hash = egressprofile.BindingHash(loaded.Profile)
	return loaded
}

func freeBrokeredRequest(t *testing.T, runsRoot string, loaded egressprofile.Loaded) spec.Request {
	t.Helper()
	req := brokeredRequest(t, runsRoot, loaded)
	routeID := "opencode-free"
	model := "opencode/space-bunny-free"
	req.Network.RouteID = &routeID
	req.Network.Model = &model
	return req
}

func TestOpenCodeFreeProvisionWorksWithoutProviderSecretStore(t *testing.T) {
	runsRoot := filepath.Join(t.TempDir(), "runs")
	if err := os.MkdirAll(runsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded := loadTestFreeEgressProfile(t)
	req := freeBrokeredRequest(t, runsRoot, loaded)
	state := &brokeredDockerState{}
	cli := brokeredCLI(t, req, loaded, state)
	runtime := newBrokeredRuntime(t, runsRoot, loaded, nil, cli)

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
	egress := att["egress"].(map[string]any)
	if egress["route_id"] != "opencode-free" ||
		egress["model"] != "opencode/space-bunny-free" ||
		egress["llm_port"] != float64(8888) ||
		egress["provider_secret_in_worker"] != false ||
		egress["attempt_token_scoped"] != false ||
		egress["direct_egress_blocked"] != true {
		t.Fatalf("unexpected free egress attestation: %v", egress)
	}

	workerArgs := strings.Join(state.workerCreate, " ")
	for _, expected := range []string{
		"HTTPS_PROXY=http://awf-egress:8888",
		"HTTP_PROXY=http://awf-egress:8888",
	} {
		if !strings.Contains(workerArgs, expected) {
			t.Fatalf("worker create argv missing %q: %s", expected, workerArgs)
		}
	}
	if strings.Contains(workerArgs, "provider-secret") ||
		strings.Contains(workerArgs, "attempt-token") {
		t.Fatal("free worker create argv leaked secret/token material")
	}

	gatewayArgs := strings.Join(state.gatewayCreate, " ")
	if !strings.Contains(gatewayArgs, "--mode opencode-free-connect") ||
		!strings.Contains(gatewayArgs, "--proxy-host opencode.ai") ||
		!strings.Contains(gatewayArgs, "--proxy-port 443") {
		t.Fatalf("unexpected free gateway argv: %s", gatewayArgs)
	}
	if strings.Contains(gatewayArgs, "--mount") ||
		strings.Contains(gatewayArgs, "--provider-secret-file") ||
		strings.Contains(gatewayArgs, "--attempt-token-sha256") {
		t.Fatal("free gateway create argv contains secret-backed controls")
	}
	if _, err := os.Lstat(filepath.Join(req.RunRoot, "egress")); !os.IsNotExist(err) {
		t.Fatalf("free route created attempt-token directory: %v", err)
	}
}
