package main

import (
	"context"
	"log/slog"
	"math/rand/v2"
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
	"github.com/thiagomontozo/netscope-agent/internal/executor"
	"github.com/thiagomontozo/netscope-agent/internal/heartbeat"
	"github.com/thiagomontozo/netscope-agent/internal/identity"
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
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"github.com/thiagomontozo/netscope-agent/internal/spool"
)

const version = "0.2.0-experimental"

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}
	logger := logging.New(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := nprocess.Runner{MaxStdout: cfg.MaxStdoutBytes, MaxStderr: cfg.MaxStderrBytes}
	registry, err := modules.NewRegistry(ping.New(runner), route.New(runner), dns.New(), tcp.New(), httpmodule.New(), tlsmodule.New(), nmap.NewDiscovery(runner), nmap.NewServices(runner), tshark.New(runner, cfg.DataDir), zeek.New(runner, cfg.DataDir), suricata.New(runner, cfg.DataDir), iperf.New(runner))
	if err != nil {
		logger.Error("module registry failed", "error", err)
		os.Exit(1)
	}
	discoveryCtx, cancelDiscovery := context.WithTimeout(ctx, 15*time.Second)
	capabilityReport := capabilities.Discover(discoveryCtx, "", registry)
	cancelDiscovery()

	storedIdentity, err := identity.Load(cfg.DataDir)
	if err != nil {
		logger.Error("identity load failed", "error", err)
		os.Exit(1)
	}
	bootstrapHTTP, err := newHTTPClient(cfg, nil)
	if err != nil {
		logger.Error("bootstrap TLS configuration failed", "error", err)
		os.Exit(1)
	}
	bootstrap, err := client.New(cfg.ControlPlaneURL, bootstrapHTTP, version)
	if err != nil {
		logger.Error("bootstrap client configuration failed", "error", err)
		os.Exit(1)
	}
	id, enrolled, err := enrollment.Ensure(ctx, cfg.DataDir, cfg.AgentName, cfg.EnrollmentToken, version, cfg.NetworkZone, capabilityReport.Summary(), bootstrap)
	bootstrap.CloseIdleConnections()
	if err != nil {
		logger.Error("agent identity unavailable", "error", err)
		os.Exit(1)
	}
	if storedIdentity == nil && !enrolled {
		logger.Error("identity state is inconsistent")
		os.Exit(1)
	}
	cfg.EnrollmentToken = ""

	httpClient, err := newHTTPClient(cfg, id)
	if err != nil {
		logger.Error("mTLS configuration failed", "error", err)
		os.Exit(1)
	}
	api, err := client.New(cfg.ControlPlaneURL, httpClient, version)
	if err != nil {
		logger.Error("client initialization failed", "error", err)
		os.Exit(1)
	}
	defer api.CloseIdleConnections()
	if time.Until(id.CertificateExpiry) <= 14*24*time.Hour {
		pending, generateErr := identity.Generate(cfg.AgentName, "")
		if generateErr != nil {
			logger.Error("certificate rotation key generation failed", "error", generateErr)
			os.Exit(1)
		}
		rotationCtx, cancelRotation := context.WithTimeout(ctx, cfg.RequestTimeout)
		rotation, rotationErr := api.RotateIdentity(rotationCtx, pending.CSRPEM)
		cancelRotation()
		if rotationErr != nil {
			logger.Error("certificate rotation request failed", "agentId", id.AgentID, "error", rotationErr)
			os.Exit(1)
		}
		stage, stageErr := identity.StageRotation(cfg.DataDir, pending, rotation)
		if stageErr != nil {
			logger.Error("certificate rotation validation failed", "agentId", id.AgentID, "error", stageErr)
			os.Exit(1)
		}
		if activateErr := identity.ActivateRotation(cfg.DataDir, stage); activateErr != nil {
			logger.Error("certificate rotation activation failed", "agentId", id.AgentID, "error", activateErr)
			os.Exit(1)
		}
		confirmCtx, cancelConfirm := context.WithTimeout(ctx, cfg.RequestTimeout)
		confirmErr := api.ConfirmIdentityRotation(confirmCtx, rotation.CertificateID)
		cancelConfirm()
		if confirmErr != nil {
			_ = identity.RollbackRotation(cfg.DataDir)
			logger.Error("certificate rotation confirmation failed; local identity rolled back", "agentId", id.AgentID, "error", confirmErr)
			os.Exit(1)
		}
		id, err = identity.Load(cfg.DataDir)
		if err != nil {
			logger.Error("rotated identity could not be loaded", "error", err)
			os.Exit(1)
		}
		httpClient, err = newHTTPClient(cfg, id)
		if err != nil {
			logger.Error("rotated mTLS configuration failed", "error", err)
			os.Exit(1)
		}
		api.CloseIdleConnections()
		api, err = client.New(cfg.ControlPlaneURL, httpClient, version)
		if err != nil {
			logger.Error("rotated client initialization failed", "error", err)
			os.Exit(1)
		}
		defer api.CloseIdleConnections()
		if err := identity.CommitRotation(cfg.DataDir); err != nil {
			logger.Warn("certificate rotation rollback cleanup failed", "agentId", id.AgentID, "error", err)
		}
		logger.Info("agent certificate rotated", "agentId", id.AgentID, "expiresAt", id.CertificateExpiry)
	}

	capabilityReport.Manifest.AgentID = id.AgentID
	capabilityCtx, cancelCapabilities := context.WithTimeout(ctx, cfg.RequestTimeout)
	capabilityResponse, err := api.ReportCapabilities(capabilityCtx, capabilityReport.Manifest)
	cancelCapabilities()
	if err != nil {
		logger.Error("capability manifest rejected", "agentId", id.AgentID, "error", err)
		os.Exit(1)
	}
	if capabilityResponse.CapabilitiesHash != capabilityReport.Hash() {
		logger.Error("capability hash mismatch", "agentId", id.AgentID)
		os.Exit(1)
	}

	queue := &spool.Queue{Dir: filepath.Join(cfg.DataDir, "spool"), MaxBytes: cfg.MaxSpoolBytes, MaxAge: cfg.MaxSpoolAge}
	trustedSigningKeys, err := identity.TrustedSigningKeys(cfg.DataDir)
	if err != nil {
		logger.Error("job signing trust is invalid", "agentId", id.AgentID, "error", err)
		os.Exit(1)
	}
	execution := executor.New(cfg.MaxConcurrentJobs)
	execution.Registry = registry
	execution.Verifier = &security.JobVerifier{AgentID: id.AgentID, OrganizationID: id.OrganizationID, TrustedKeys: trustedSigningKeys, RequireSigned: cfg.RequireSignedJobs}
	execution.Capabilities = capabilityReport
	execution.ControlPlane = api
	execution.Spool = queue
	execution.Logger = logger
	execution.MaxJobTimeout = cfg.MaxJobTimeout
	execution.MaxResultBytes = cfg.MaxResultBytes

	heartbeatCtx, cancelHeartbeat := context.WithTimeout(ctx, cfg.RequestTimeout)
	response, err := api.Heartbeat(heartbeatCtx, heartbeat.Build(heartbeatCtx, id.AgentID, version, cfg.MaxConcurrentJobs, capabilityReport, execution, queue))
	cancelHeartbeat()
	if err == nil {
		err = protocol.RequireCompatible(response.ProtocolVersion)
	}
	if err != nil {
		logger.Error("initial heartbeat rejected", "agentId", id.AgentID, "error", err)
		os.Exit(1)
	}
	logger.Info("agent online", "agentId", id.AgentID, "protocolVersion", protocol.Version, "agentVersion", version, "compatibilityStatus", response.CompatibilityStatus, "enrolled", enrolled)

	if err := runLoop(ctx, cfg, api, execution, queue, capabilityReport, id.AgentID, logger); err != nil {
		logger.Error("agent stopped by Control Plane", "agentId", id.AgentID, "error", err)
		stop()
	}
	execution.Wait()
	finalCtx, cancelFinal := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFinal()
	_, _ = api.Heartbeat(finalCtx, heartbeat.Build(finalCtx, id.AgentID, version, cfg.MaxConcurrentJobs, capabilityReport, execution, queue))
}

func newHTTPClient(cfg config.Config, id *identity.Identity) (*http.Client, error) {
	tlsConfig, err := cfg.TLSConfig(id)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	return &http.Client{Transport: transport, Timeout: cfg.RequestTimeout}, nil
}

func runLoop(ctx context.Context, cfg config.Config, api *client.Client, execution *executor.Executor, queue *spool.Queue, capabilityReport capabilities.Report, agentID string, logger *slog.Logger) error {
	pollTimer := time.NewTimer(cfg.JobPollInterval)
	heartbeatTimer := time.NewTimer(jitter(cfg.HeartbeatInterval))
	defer pollTimer.Stop()
	defer heartbeatTimer.Stop()
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeatTimer.C:
			heartbeatCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
			response, err := api.Heartbeat(heartbeatCtx, heartbeat.Build(heartbeatCtx, agentID, version, cfg.MaxConcurrentJobs, capabilityReport, execution, queue))
			if err == nil {
				if compatibilityErr := protocol.RequireCompatible(response.ProtocolVersion); compatibilityErr != nil {
					cancel()
					return compatibilityErr
				}
				_ = queue.Flush(heartbeatCtx, api)
			}
			cancel()
			if client.IsTerminal(err) {
				return err
			}
			heartbeatTimer.Reset(jitter(cfg.HeartbeatInterval))
		case <-pollTimer.C:
			if execution.Running() >= cfg.MaxConcurrentJobs {
				pollTimer.Reset(cfg.JobPollInterval)
				continue
			}
			jobCtx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
			job, err := api.NextJob(jobCtx)
			cancel()
			if err != nil {
				if client.IsTerminal(err) {
					return err
				}
				attempt++
				delay := client.Backoff(attempt, time.Minute)
				logger.Warn("control plane unavailable; no new jobs will start", "agentId", agentID, "retryAfter", delay)
				pollTimer.Reset(delay)
				continue
			}
			attempt = 0
			pollTimer.Reset(cfg.JobPollInterval)
			if job != nil {
				if err := execution.Submit(ctx, *job); err != nil {
					logger.Warn("job rejected", "agentId", agentID, "jobId", job.JobID, "moduleId", job.ModuleID)
				}
			}
		}
	}
}

func jitter(interval time.Duration) time.Duration {
	maximum := interval / 10
	if maximum <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(int64(maximum)+1))
}
