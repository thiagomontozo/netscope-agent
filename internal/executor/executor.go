package executor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/capabilities"
	"github.com/thiagomontozo/netscope-agent/internal/evidence"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"github.com/thiagomontozo/netscope-agent/internal/spool"
)

type ControlPlane interface {
	StartJob(context.Context, string) error
	ReportResult(context.Context, protocol.JobResult) error
	ReportFailure(context.Context, protocol.JobFailure) error
	Cancellation(context.Context, string) (protocol.JobCancellation, error)
}

type Executor struct {
	Registry       *modules.Registry
	Verifier       *security.JobVerifier
	Capabilities   capabilities.Report
	ControlPlane   ControlPlane
	Spool          *spool.Queue
	Logger         *slog.Logger
	MaxJobTimeout  time.Duration
	MaxResultBytes int64
	slots          chan struct{}
	wg             sync.WaitGroup
	lastMu         sync.RWMutex
	lastResult     *protocol.LastJobResult
}

func New(maximum int) *Executor  { return &Executor{slots: make(chan struct{}, maximum)} }
func (e *Executor) Running() int { return len(e.slots) }
func (e *Executor) Wait()        { e.wg.Wait() }

func (e *Executor) LastResult() *protocol.LastJobResult {
	e.lastMu.RLock()
	defer e.lastMu.RUnlock()
	if e.lastResult == nil {
		return nil
	}
	copy := *e.lastResult
	return &copy
}

func (e *Executor) Submit(parent context.Context, job protocol.JobEnvelope) error {
	if err := e.Verifier.Verify(job); err != nil {
		e.reject(parent, job, security.FailureCode(err), err.Error(), false)
		return err
	}
	module, ok := e.Registry.Get(job.ModuleID)
	if !ok {
		err := errors.New("module is not compiled into this agent")
		e.reject(parent, job, protocol.FailureModuleUnavailable, err.Error(), false)
		return err
	}
	descriptor := module.Descriptor()
	if err := security.ValidateModuleVersion(job.ModuleVersionRequirement, descriptor.Version); err != nil {
		e.reject(parent, job, security.FailureCode(err), err.Error(), false)
		return err
	}
	if descriptor.RiskClass != job.RiskClass {
		err := errors.New("job risk class differs from the compiled module")
		e.reject(parent, job, protocol.FailureInvalidJob, err.Error(), false)
		return err
	}
	if descriptor.RequiredCapability != "" && !e.Capabilities.Has(descriptor.RequiredCapability) {
		err := errors.New("required module capability is unavailable")
		e.reject(parent, job, protocol.FailureCapabilityMissing, err.Error(), false)
		return err
	}
	if err := module.Validate(job); err != nil {
		e.reject(parent, job, protocol.FailureInvalidJob, err.Error(), false)
		return err
	}
	select {
	case e.slots <- struct{}{}:
	default:
		err := errors.New("no local execution slot is available")
		e.reject(parent, job, protocol.FailureInternal, err.Error(), true)
		return err
	}
	startCtx, cancel := context.WithTimeout(parent, 10*time.Second)
	err := e.ControlPlane.StartJob(startCtx, job.JobID)
	cancel()
	if err != nil {
		<-e.slots
		e.reject(parent, job, protocol.FailureInternal, "job start acknowledgement failed", true)
		return err
	}
	e.wg.Add(1)
	go e.execute(parent, job, module)
	return nil
}

func (e *Executor) execute(parent context.Context, job protocol.JobEnvelope, module modules.Module) {
	defer func() { <-e.slots; e.wg.Done() }()
	timeout := time.Duration(job.TimeoutSeconds) * time.Second
	if e.MaxJobTimeout > 0 && timeout > e.MaxJobTimeout {
		timeout = e.MaxJobTimeout
	}
	if remaining := time.Until(job.ExpiresAt); remaining < timeout {
		timeout = remaining
	}
	if timeout <= 0 {
		e.reject(context.WithoutCancel(parent), job, protocol.FailureJobExpired, "job expired before execution", false)
		return
	}
	timeoutContext, cancelTimeout := context.WithTimeout(parent, timeout)
	ctx, cancel := context.WithCancel(timeoutContext)
	defer cancelTimeout()
	defer cancel()
	cancelled := make(chan struct{}, 1)
	go e.monitorCancellation(ctx, cancel, cancelled, job.JobID)
	release, err := e.Registry.Acquire(ctx, job.ModuleID)
	if err != nil {
		e.reject(context.WithoutCancel(parent), job, protocol.FailureInternal, "module execution slot could not be reserved", true)
		return
	}
	defer release()
	checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
	cancellation, cancellationErr := e.ControlPlane.Cancellation(checkCtx, job.JobID)
	checkCancel()
	if cancellationErr == nil && cancellation.CancellationRequested {
		e.recordLast(job.JobID, "CANCELLED", time.Now().UTC())
		return
	}

	started := time.Now().UTC()
	result, runErr := module.Execute(ctx, job)
	if runErr != nil {
		select {
		case <-cancelled:
			e.recordLast(job.JobID, "CANCELLED", time.Now().UTC())
			return
		default:
		}
		code := protocol.FailureProcessFailed
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = protocol.FailureTimeout
		}
		e.reject(context.WithoutCancel(parent), job, code, safeSummary(runErr.Error()), code == protocol.FailureInternal)
		return
	}
	if result.StartedAt.IsZero() {
		result.StartedAt = started
	}
	if result.CompletedAt.IsZero() {
		result.CompletedAt = time.Now().UTC()
	}
	wireResult, err := e.normalize(job, result)
	if err != nil {
		e.reject(context.WithoutCancel(parent), job, protocol.FailureInternal, "result normalization failed", false)
		return
	}
	deliveryCtx, deliveryCancel := context.WithTimeout(context.WithoutCancel(parent), 30*time.Second)
	err = e.ControlPlane.ReportResult(deliveryCtx, wireResult)
	deliveryCancel()
	if err != nil {
		if enqueueErr := e.Spool.Enqueue("result", wireResult); enqueueErr != nil {
			e.Logger.Error("result delivery and spool failed", "agentId", wireResult.AgentID, "jobId", job.JobID, "moduleId", job.ModuleID)
		}
	}
	e.recordLast(job.JobID, "SUCCEEDED", wireResult.CompletedAt)
	e.Logger.Info("job completed", "agentId", wireResult.AgentID, "jobId", job.JobID, "moduleId", job.ModuleID, "truncated", wireResult.Truncated)
}

func (e *Executor) monitorCancellation(ctx context.Context, cancel context.CancelFunc, cancelled chan<- struct{}, jobID string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
			status, err := e.ControlPlane.Cancellation(checkCtx, jobID)
			checkCancel()
			if err == nil && status.CancellationRequested {
				select {
				case cancelled <- struct{}{}:
				default:
				}
				cancel()
				return
			}
		}
	}
}

func (e *Executor) normalize(job protocol.JobEnvelope, result jobs.ModuleResult) (protocol.JobResult, error) {
	resultIdentity, err := evidence.NewID()
	if err != nil {
		return protocol.JobResult{}, err
	}
	observations := make([]protocol.Observation, 0, len(result.Observations))
	structuredObservations := make([]map[string]any, 0, len(result.Observations))
	for _, observation := range result.Observations {
		observations = append(observations, protocol.Observation{AssetID: job.AssetID, Category: observation.Kind, Status: protocol.StatusInformational, Severity: "INFORMATIONAL", Confidence: protocol.ConfidenceHigh, Title: observation.Message, Summary: observation.Message, Meaning: "The module obtained this direct technical result from the authorized target.", Impact: "Operational impact requires Control Plane correlation with other evidence and vantage points.", SuggestedAction: "Review the structured technical evidence and compare with relevant observations.", ObservedAt: result.CompletedAt})
		structuredObservations = append(structuredObservations, map[string]any{"category": observation.Kind, "summary": observation.Message, "data": observation.Data})
	}
	metrics := make([]protocol.Metric, 0, len(result.Metrics))
	for name, value := range result.Metrics {
		if !allowedMetric(name) {
			continue
		}
		metricValue := value
		status := protocol.StatusInformational
		if name == "AVAILABILITY" {
			if value >= 1 {
				status = protocol.StatusHealthy
			} else {
				status = protocol.StatusWarning
			}
		}
		metrics = append(metrics, protocol.Metric{Name: name, NumericValue: &metricValue, Status: status, ObservedAt: result.CompletedAt})
	}
	structured := map[string]any{"moduleId": job.ModuleID, "summary": result.Summary, "observations": structuredObservations, "metrics": result.Metrics, "truncated": result.Truncated}
	manifest, err := evidence.NewManifest(job.ModuleID, result.Summary, artifactKind(job.ModuleID), structured)
	if err != nil {
		return protocol.JobResult{}, err
	}
	warnings := result.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	wire := protocol.JobResult{ProtocolVersion: protocol.Version, ResultIdentity: resultIdentity, ResultVersion: 1, JobID: job.JobID, AgentID: job.AgentID, ModuleID: job.ModuleID, Status: "SUCCEEDED", StartedAt: result.StartedAt, CompletedAt: result.CompletedAt, Summary: safeSummary(result.Summary), Observations: observations, Metrics: metrics, Warnings: warnings, EvidenceManifest: []protocol.EvidenceManifest{manifest}, ToolVersion: result.ToolVersion, Truncated: result.Truncated}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return protocol.JobResult{}, err
	}
	if int64(len(encoded)) > e.MaxResultBytes {
		wire.Observations = []protocol.Observation{}
		wire.EvidenceManifest = []protocol.EvidenceManifest{}
		wire.Warnings = append(wire.Warnings, "Detailed result exceeded the local protocol limit and was omitted.")
		wire.Truncated = true
		encoded, _ = json.Marshal(wire)
		if int64(len(encoded)) > e.MaxResultBytes {
			return protocol.JobResult{}, errors.New("result exceeds local protocol limit")
		}
	}
	return wire, nil
}

func (e *Executor) reject(ctx context.Context, job protocol.JobEnvelope, code protocol.FailureCode, summary string, retryable bool) {
	failure := protocol.JobFailure{ProtocolVersion: protocol.Version, JobID: job.JobID, AgentID: job.AgentID, Code: code, Summary: safeSummary(summary), OccurredAt: time.Now().UTC(), Retryable: retryable}
	deliveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	err := e.ControlPlane.ReportFailure(deliveryCtx, failure)
	cancel()
	if err != nil {
		_ = e.Spool.Enqueue("failure", failure)
	}
	e.recordLast(job.JobID, "FAILED", failure.OccurredAt)
	e.Logger.Warn("job rejected or failed", "agentId", job.AgentID, "jobId", job.JobID, "moduleId", job.ModuleID, "code", code)
}

func (e *Executor) recordLast(jobID, status string, completedAt time.Time) {
	e.lastMu.Lock()
	defer e.lastMu.Unlock()
	e.lastResult = &protocol.LastJobResult{JobID: jobID, Status: status, CompletedAt: completedAt}
}

func safeSummary(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if value == "" {
		value = "Agent could not complete the requested operation."
	}
	if len(value) > 2000 {
		value = value[:2000]
	}
	return value
}

func allowedMetric(name string) bool {
	switch name {
	case "AVAILABILITY", "LATENCY_MS", "PACKET_LOSS_PERCENT", "DNS_DURATION_MS", "TCP_CONNECT_DURATION_MS", "TLS_DAYS_UNTIL_EXPIRATION", "HTTP_DURATION_MS", "HTTP_STATUS":
		return true
	default:
		return false
	}
}

func artifactKind(moduleID string) string {
	switch moduleID {
	case "network.dns":
		return "DNS_RESPONSE"
	case "network.tls":
		return "TLS_METADATA"
	case "network.http":
		return "HTTP_TRANSACTION"
	case "network.route":
		return "ROUTE_HOPS"
	case "nmap.discovery", "nmap.services":
		return "NMAP_RESULT"
	case "traffic.zeek":
		return "ZEEK_EVENT"
	case "security.suricata":
		return "SURICATA_EVENT"
	default:
		return "STRUCTURED_RESULT"
	}
}
