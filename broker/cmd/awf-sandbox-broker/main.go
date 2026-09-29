package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"autonomous-worker/broker/internal/dockerruntime"
	"autonomous-worker/broker/internal/egressprofile"
	"autonomous-worker/broker/internal/secretstore"
	"autonomous-worker/broker/internal/server"
	"autonomous-worker/broker/internal/workspace"
)

func main() {
	var (
		socketPath          = flag.String("socket", "/run/autonomous-worker/sandbox-broker.sock", "Unix socket path")
		controllerUID       = flag.String("controller-uid", "", "authorized non-root Controller UID")
		runsRoot            = flag.String("runs-root", "/var/lib/autonomous-worker/runs", "root-owned broker runs root")
		brokerBuild         = flag.String("build", "dev", "broker build identifier")
		probeOnly           = flag.Bool("probe-only", false, "probe privileged prerequisites and exit")
		machineID           = flag.String("machine-id", "production-vps", "broker machine identity")
		egressProfilesRoot  = flag.String("egress-profiles-root", "/etc/autonomous-worker/egress-profiles", "root-owned trusted egress profile directory")
		providerSecretsRoot = flag.String("provider-secrets-root", "/var/lib/autonomous-worker/secrets", "root-owned provider secret source directory")
		egressRuntimeRoot   = flag.String("egress-runtime-root", "/var/lib/autonomous-worker/egress-runtime", "root-owned ephemeral gateway-only secret staging directory")
	)
	flag.Parse()

	if *controllerUID == "" {
		fmt.Fprintln(os.Stderr, "--controller-uid is required")
		os.Exit(2)
	}
	uid, err := server.ParseControllerUID(*controllerUID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	workspaceManager, err := workspace.New(workspace.Config{
		RunsRoot:    *runsRoot,
		BrokerBuild: *brokerBuild,
		RequireRoot: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	egressProfiles, err := egressprofile.NewStore(*egressProfilesRoot, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	providerSecrets, err := secretstore.New(secretstore.Config{
		Root:        *providerSecretsRoot,
		RuntimeRoot: *egressRuntimeRoot,
		GatewayUID:  65532,
		GatewayGID:  65532,
		RequireRoot: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	dockerRuntime, err := dockerruntime.New(dockerruntime.Config{
		RunsRoot:        *runsRoot,
		BrokerBuild:     *brokerBuild,
		MachineID:       *machineID,
		RequireRoot:     true,
		EgressProfiles:  egressProfiles,
		ProviderSecrets: providerSecrets,
	}, dockerruntime.ExecCLI{Binary: "/usr/bin/docker"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	probeErr := dockerRuntime.Probe(probeCtx)
	probeCancel()
	if probeErr != nil {
		fmt.Fprintln(os.Stderr, "docker runtime probe failed; broker will stay not-ready:", probeErr)
	}

	if *probeOnly {
		status := map[string]any{
			"status":                  "ready",
			"broker_build":            *brokerBuild,
			"machine_id":              *machineID,
			"controller_uid":          uid,
			"runtime_ready":           dockerRuntime.Ready(),
			"workspace_manager_ready": workspaceManager.Ready(),
		}
		if probeErr != nil || !dockerRuntime.Ready() || !workspaceManager.Ready() {
			status["status"] = "not_ready"
		}
		if err := json.NewEncoder(os.Stdout).Encode(status); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if status["status"] != "ready" {
			os.Exit(1)
		}
		return
	}

	s, err := server.New(server.Config{
		ControllerUID: uid,
		MachineID:     *machineID,
		RunsRoot:      *runsRoot,
		BrokerBuild:   *brokerBuild,
		RequireRoot:   true,
	}, dockerRuntime, workspaceManager)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := s.ListenAndServeUnix(ctx, *socketPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
