package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/capabilities"
	"github.com/thiagomontozo/netscope-agent/internal/client"
	"github.com/thiagomontozo/netscope-agent/internal/config"
	"github.com/thiagomontozo/netscope-agent/internal/enrollment"
	"github.com/thiagomontozo/netscope-agent/internal/evidence"
	"github.com/thiagomontozo/netscope-agent/internal/executor"
	"github.com/thiagomontozo/netscope-agent/internal/heartbeat"
	"github.com/thiagomontozo/netscope-agent/internal/identity"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/logging"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"github.com/thiagomontozo/netscope-agent/internal/modules/dns"
	httpmodule "github.com/thiagomontozo/netscope-agent/internal/modules/http"
	"github.com/thiagomontozo/netscope-agent/internal/modules/iperf"
	"github.com/thiagomontozo/netscope-agent/internal/modules/nmap"
	"github.com/thiagomontozo/netscope-agent/internal/modules/ping"
	"github.com/thiagomontozo/netscope-agent/internal/modules/route"
	"github.com/thiagomontozo/netscope-agent/internal/modules/suricata"
	"github.com/thiagomontozo/netscope-agent/internal/modules/tcp"
	tlsmodule "github.com/thiagomontozo/netscope-agent/internal/modules/tls"
	"github.com/thiagomontozo/netscope-agent/internal/modules/tshark"
	"github.com/thiagomontozo/netscope-agent/internal/modules/zeek"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"github.com/thiagomontozo/netscope-agent/internal/spool"
)

const version = "0.1.0-experimental"

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}
	log := logging.New(cfg.LogLevel)
	if cfg.DevelopmentInsecureTLS {
		log.Error("CRITICAL: TLS certificate verification is disabled by explicit development configuration")
	}
	tlsConfig, err := cfg.TLSConfig()
	if err != nil {
		log.Error("TLS configuration failed", "error", err)
		os.Exit(1)
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	httpClient := &http.Client{Transport: transport, Timeout: cfg.RequestTimeout}
	bootstrap, err := client.New(cfg.ControlPlaneURL, httpClient, version, nil)
	if err != nil {
		log.Error("client configuration failed", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	existingIdentity, loadIdentityErr := identity.Load(cfg.DataDir)
	if loadIdentityErr != nil {
		log.Error("identity load failed", "error", loadIdentityErr)
		os.Exit(1)
	}
	id, err := enrollment.Ensure(ctx, cfg.DataDir, cfg.AgentName, cfg.EnrollmentToken, version, bootstrap)
	if err != nil {
		log.Error("identity unavailable", "error", err)
		os.Exit(1)
	}
	api, err := client.New(cfg.ControlPlaneURL, httpClient, version, id)
	if err != nil {
		log.Error("client initialization failed", "error", err)
		os.Exit(1)
	}
	defer api.CloseIdleConnections()
	keyPath := cfg.ControlPlaneSigningKeyPath
	if keyPath == "" {
		keyPath = filepath.Join(cfg.DataDir, "identity", "control-plane-signing-key")
	}
	key, err := security.LoadControlPlaneKey(keyPath)
	if err != nil {
		log.Error("job verification key unavailable", "error", err)
		os.Exit(1)
	}
	discoveryCtx, cancelDiscovery := context.WithTimeout(ctx, 15*time.Second)
	caps := capabilities.Discover(discoveryCtx)
	cancelDiscovery()
	runner := nprocess.Runner{MaxStdout: cfg.MaxStdoutBytes, MaxStderr: cfg.MaxStderrBytes}
	registry, err := modules.NewRegistry(ping.New(runner), route.New(runner), dns.New(), tcp.New(), httpmodule.New(), tlsmodule.New(), nmap.NewDiscovery(runner), nmap.NewServices(runner), tshark.New(runner, cfg.DataDir), zeek.New(runner, cfg.DataDir), suricata.New(runner, cfg.DataDir), iperf.New(runner))
	if err != nil {
		log.Error("module registry failed", "error", err)
		os.Exit(1)
	}
	queue := spool.Queue{Dir: filepath.Join(cfg.DataDir, "spool"), MaxBytes: cfg.MaxSpoolBytes, MaxAge: cfg.MaxSpoolAge}
	exec := executor.New(cfg.MaxConcurrentJobs)
	exec.Registry = registry
	exec.Verifier = security.JobVerifier{AgentID: id.AgentID, PublicKey: key}
	exec.Capabilities = caps
	exec.Artifacts = evidence.Manager{DataDir: cfg.DataDir, MaxArtifactBytes: cfg.MaxArtifactBytes, HTTP: httpClient}
	exec.ControlPlane = api
	exec.Spool = queue
	exec.Logger = log
	exec.DefaultTimeout = cfg.DefaultTimeout
	exec.MaxResultBytes = cfg.MaxResultBytes
	_ = api.ReportEvent(ctx, map[string]any{"type": "agent.started", "timestamp": time.Now().UTC(), "agentId": id.AgentID})
	if existingIdentity == nil {
		_ = api.ReportEvent(ctx, map[string]any{"type": "agent.enrolled", "timestamp": time.Now().UTC(), "agentId": id.AgentID})
	}
	capabilityPayload := map[string]any{"agentId": id.AgentID, "agentVersion": version, "protocolVersion": jobs.ProtocolVersion, "supportedModules": registry.Descriptors(), "capabilities": caps}
	if err := api.ReportCapabilities(ctx, capabilityPayload); err == nil {
		_ = api.ReportEvent(ctx, map[string]any{"type": "agent.capabilities_changed", "timestamp": time.Now().UTC(), "agentId": id.AgentID, "capabilitiesHash": caps.Hash()})
	}
	runLoop(ctx, cfg, api, exec, queue, caps, id.AgentID, log)
	exec.Wait()
	finalCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = api.Heartbeat(finalCtx, heartbeat.Build(finalCtx, id.AgentID, version, jobs.ProtocolVersion, cfg.Zone, cfg.MaxConcurrentJobs, caps, exec, queue))
	_ = api.ReportEvent(finalCtx, map[string]any{"type": "agent.shutdown", "timestamp": time.Now().UTC(), "agentId": id.AgentID})
}

func runLoop(ctx context.Context, cfg config.Config, api *client.Client, exec *executor.Executor, queue spool.Queue, caps capabilities.Report, agentID string, log *slog.Logger) {
	poll := time.NewTicker(cfg.JobPollInterval)
	defer poll.Stop()
	heart := time.NewTicker(30 * time.Second)
	defer heart.Stop()
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-heart.C:
			hbCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
			err := api.Heartbeat(hbCtx, heartbeat.Build(hbCtx, agentID, version, jobs.ProtocolVersion, cfg.Zone, cfg.MaxConcurrentJobs, caps, exec, queue))
			if err == nil {
				_ = queue.Flush(hbCtx, api)
			}
			cancel()
		case <-poll.C:
			jobCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
			job, err := api.NextJob(jobCtx)
			cancel()
			if err != nil {
				attempt++
				delay := client.Backoff(attempt, time.Minute)
				log.Warn("control plane unavailable; no new jobs will start", "retryAfter", delay, "error", err)
				poll.Reset(delay)
				continue
			}
			if attempt > 0 {
				attempt = 0
				poll.Reset(cfg.JobPollInterval)
			}
			if job != nil {
				if err := exec.Submit(ctx, *job); err != nil {
					log.Warn("job rejected", "jobId", job.JobID, "moduleId", job.ModuleID, "error", err)
				}
			}
		}
	}
}
