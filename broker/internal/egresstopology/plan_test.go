package egresstopology

import (
	"os"
	"strings"
	"testing"
	"time"

	"autonomous-worker/broker/internal/egressprofile"
	"autonomous-worker/broker/internal/spec"
)

const testRunsRoot = "/var/lib/autonomous-worker/runs"

func testClock() time.Time {
	return time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
}

func testRequest() spec.Request {
	var req spec.Request
	req.SchemaVersion = "1.0"
	req.RequestID = "req-egress-001"
	req.TaskID = "task-egress-001"
	req.AttemptID = "attempt-egress-001"
	req.MachineID = "production-vps"
	req.Tier = "T1"
	req.RunRoot = testRunsRoot + "/attempt-egress-001"
	req.Workspace.Source = req.RunRoot + "/repo"
	req.Workspace.MountPath = "/workspace"
	req.Workspace.BaseSHA = "0123456789abcdef0123456789abcdef01234567"
	req.Workspace.ControllerGID = 1000
	req.Image.Reference = "autonomous-worker-runtime"
	req.Image.Digest = "sha256:" + strings.Repeat("a", 64)
	profileID := "llm-default"
	routeID := "openai-responses"
	model := "gpt-5.2"
	req.Network.Profile = "brokered"
	req.Network.EgressProfileID = &profileID
	req.Network.RouteID = &routeID
	req.Network.Model = &model
	req.Resources.CPU = 1
	req.Resources.MemoryBytes = 1 << 30
	req.Resources.PIDs = 256
	req.Resources.TmpfsBytes = 256 << 20
	req.Resources.TimeoutSeconds = 1800
	req.Command.Argv = []string{
		"opencode", "run", "--standalone", "--format", "json", "--agent", "build", "--title", "AWF Worker", "--file", "control/task.md",
		"Execute the task described in the attached task file. Work only in repo/.",
	}
	req.PolicyHash = strings.Repeat("b", 64)
	req.ExpiresAt = testClock().Add(5 * time.Minute).Format(time.RFC3339)
	req.WorkspaceLeaseID = "lease-egress-001"
	req.WorkspaceLeaseHash = strings.Repeat("d", 64)
	return req
}

func loadedProfile(t *testing.T) egressprofile.Loaded {
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
		Path:    "/etc/autonomous-worker/egress/llm-default.json",
	}
}

func compileInput(t *testing.T) CompileInput {
	t.Helper()
	loaded := loadedProfile(t)
	req := testRequest()
	req.Network.EgressProfileHash = &loaded.Hash
	return CompileInput{
		Request:            req,
		LoadedProfile:      loaded,
		RunsRoot:           testRunsRoot,
		ProviderSecretPath: "/var/lib/autonomous-worker/secrets/providers/openai-main",
		AttemptTokenPath:   req.RunRoot + "/egress/attempt-token",
		AttemptTokenSHA256: strings.Repeat("f", 64),
		Now:                testClock(),
		Limits:             spec.DefaultLimits(),
	}
}

func TestCompileEnforcesTwoNetworkLeastAuthorityTopology(t *testing.T) {
	input := compileInput(t)
	plan, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}

	internalArgs := strings.Join(plan.InternalNetworkCreateArgs, " ")
	if !strings.Contains(internalArgs, "network create --driver bridge --internal") {
		t.Fatalf("internal network is not Docker --internal: %s", internalArgs)
	}
	egressArgs := strings.Join(plan.EgressNetworkCreateArgs, " ")
	if strings.Contains(egressArgs, "--internal") {
		t.Fatalf("egress bridge must provide outbound NAT for the gateway: %s", egressArgs)
	}

	workerArgs := strings.Join(plan.Worker.CreateArgs, " ")
	if !strings.Contains(workerArgs, "--network "+plan.InternalNetworkName) {
		t.Fatalf("worker is not attached to the internal network: %s", workerArgs)
	}
	if strings.Contains(workerArgs, plan.EgressNetworkName) {
		t.Fatalf("worker must never be attached to the egress network: %s", workerArgs)
	}
	if strings.Contains(workerArgs, input.ProviderSecretPath) {
		t.Fatal("provider secret path leaked into worker Docker argv")
	}

	gatewayArgs := strings.Join(plan.Gateway.CreateArgs, " ")
	if !strings.Contains(gatewayArgs, "--network "+plan.InternalNetworkName) {
		t.Fatal("gateway is not initially attached to the internal network")
	}
	if !strings.Contains(gatewayArgs, "--network-alias awf-egress") {
		t.Fatal("gateway does not expose the fixed internal alias")
	}
	if !strings.Contains(gatewayArgs, "src="+input.ProviderSecretPath+",dst=/run/secrets/provider,readonly") {
		t.Fatal("provider secret is not mounted read-only into gateway only")
	}
	if !strings.Contains(gatewayArgs, "--allowed-model gpt-5.2") {
		t.Fatal("gateway is not narrowed to the request-bound model")
	}
	if strings.Contains(gatewayArgs, "gpt-unapproved") {
		t.Fatal("gateway argv contains an unapproved model")
	}

	connectArgs := strings.Join(plan.GatewayConnectEgressArgs, " ")
	if connectArgs != "network connect "+plan.EgressNetworkName+" "+plan.Gateway.ContainerName {
		t.Fatalf("unexpected gateway egress connect command: %s", connectArgs)
	}
}

func TestCompileGatewayReceivesOnlyAttemptTokenHashNotRawToken(t *testing.T) {
	input := compileInput(t)
	plan, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	gatewayArgs := strings.Join(plan.Gateway.CreateArgs, " ")
	if !strings.Contains(gatewayArgs, "--attempt-token-sha256 "+input.AttemptTokenSHA256) {
		t.Fatal("gateway did not receive attempt token hash")
	}
	if strings.Contains(gatewayArgs, "dummy-attempt-token") {
		t.Fatal("raw attempt token must not be present in gateway argv")
	}
}

func TestCompileRejectsProfileHashSubstitution(t *testing.T) {
	input := compileInput(t)
	bad := strings.Repeat("0", 64)
	input.Request.Network.EgressProfileHash = &bad
	if _, err := Compile(input); err == nil || !strings.Contains(err.Error(), "hash binding mismatch") {
		t.Fatalf("expected profile hash mismatch, got %v", err)
	}
}

func TestCompileRejectsModelSubstitution(t *testing.T) {
	input := compileInput(t)
	model := "gpt-unapproved"
	input.Request.Network.Model = &model
	if _, err := Compile(input); err == nil || !strings.Contains(err.Error(), "model is not allowed") {
		t.Fatalf("expected model allowlist rejection, got %v", err)
	}
}

func TestCompileRejectsProviderSecretUnderRunRoot(t *testing.T) {
	input := compileInput(t)
	input.ProviderSecretPath = input.Request.RunRoot + "/provider-secret"
	if _, err := Compile(input); err == nil || !strings.Contains(err.Error(), "outside the broker runs root") {
		t.Fatalf("expected provider secret path rejection, got %v", err)
	}
}

func TestCompileRejectsAttemptTokenPathSwap(t *testing.T) {
	input := compileInput(t)
	input.AttemptTokenPath = input.Request.RunRoot + "/control/token"
	if _, err := Compile(input); err == nil || !strings.Contains(err.Error(), "derived from run_root") {
		t.Fatalf("expected attempt token path rejection, got %v", err)
	}
}

func TestCompileUsesOnlyRequestBoundModelEvenIfTrustedRouteAllowsMore(t *testing.T) {
	input := compileInput(t)
	input.LoadedProfile.Profile.Routes[0].Models = append(
		input.LoadedProfile.Profile.Routes[0].Models,
		"gpt-second-approved",
	)
	input.LoadedProfile.Hash = egressprofile.BindingHash(input.LoadedProfile.Profile)
	input.Request.Network.EgressProfileHash = &input.LoadedProfile.Hash

	plan, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	gatewayArgs := strings.Join(plan.Gateway.CreateArgs, " ")
	if strings.Contains(gatewayArgs, "gpt-second-approved") {
		t.Fatal("gateway widened model allowlist beyond request-bound model")
	}
	if strings.Count(gatewayArgs, "--allowed-model") != 1 {
		t.Fatalf("expected exactly one allowed model, got: %s", gatewayArgs)
	}
}

func freeLoadedProfile(t *testing.T) egressprofile.Loaded {
	t.Helper()
	loaded := loadedProfile(t)
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

func freeCompileInput(t *testing.T) CompileInput {
	t.Helper()
	loaded := freeLoadedProfile(t)
	req := testRequest()
	profileID := loaded.Profile.ProfileID
	profileHash := loaded.Hash
	routeID := "opencode-free"
	model := "opencode/space-bunny-free"
	req.Network.EgressProfileID = &profileID
	req.Network.EgressProfileHash = &profileHash
	req.Network.RouteID = &routeID
	req.Network.Model = &model
	return CompileInput{
		Request:       req,
		LoadedProfile: loaded,
		RunsRoot:      testRunsRoot,
		Now:           testClock(),
		Limits:        spec.DefaultLimits(),
	}
}

func TestCompileOpenCodeFreeConnectIsSecretlessAndProxyBound(t *testing.T) {
	input := freeCompileInput(t)
	plan, err := Compile(input)
	if err != nil {
		t.Fatal(err)
	}

	workerArgs := strings.Join(plan.Worker.CreateArgs, " ")
	for _, expected := range []string{
		"--network " + plan.InternalNetworkName,
		"HTTPS_PROXY=http://awf-egress:8888",
		"HTTP_PROXY=http://awf-egress:8888",
		"NO_PROXY=127.0.0.1,localhost,::1",
	} {
		if !strings.Contains(workerArgs, expected) {
			t.Fatalf("worker argv missing %q: %s", expected, workerArgs)
		}
	}
	if strings.Contains(workerArgs, plan.EgressNetworkName) {
		t.Fatal("free-model worker is directly attached to outbound network")
	}
	if strings.Contains(workerArgs, "attempt-token") ||
		strings.Contains(workerArgs, "provider-secret") {
		t.Fatal("free-model worker argv contains secret/token material")
	}

	gatewayArgs := strings.Join(plan.Gateway.CreateArgs, " ")
	for _, expected := range []string{
		"--mode opencode-free-connect",
		"--listen :8888",
		"--proxy-host opencode.ai",
		"--proxy-port 443",
	} {
		if !strings.Contains(gatewayArgs, expected) {
			t.Fatalf("gateway argv missing %q: %s", expected, gatewayArgs)
		}
	}
	if strings.Contains(gatewayArgs, "--mount") ||
		strings.Contains(gatewayArgs, "--provider-secret-file") ||
		strings.Contains(gatewayArgs, "--attempt-token-sha256") {
		t.Fatal("free CONNECT gateway contains provider-secret/token controls")
	}
	if len(plan.Gateway.Mounts) != 0 {
		t.Fatalf("free CONNECT gateway mounts = %v, want none", plan.Gateway.Mounts)
	}
	if plan.AttemptTokenPath != "" {
		t.Fatalf("free CONNECT plan unexpectedly created attempt token path %q", plan.AttemptTokenPath)
	}
}

func TestCompileOpenCodeFreeConnectRejectsSecretInputs(t *testing.T) {
	input := freeCompileInput(t)
	input.ProviderSecretPath = "/var/lib/autonomous-worker/secrets/providers/unexpected"
	if _, err := Compile(input); err == nil || !strings.Contains(err.Error(), "must not receive") {
		t.Fatalf("expected secret material rejection, got %v", err)
	}
}
