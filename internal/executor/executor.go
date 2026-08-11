package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/capabilities"
	"github.com/thiagomontozo/netscope-agent/internal/evidence"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"github.com/thiagomontozo/netscope-agent/internal/spool"
)

type ControlPlane interface {
	ReportResult(context.Context, jobs.ModuleResult) error
	ReportEvent(context.Context, any) error
	IsCancelled(context.Context, string) (bool, error)
}
type Executor struct {
	Registry       *modules.Registry
	Verifier       security.JobVerifier
	Capabilities   capabilities.Report
	Artifacts      evidence.Manager
	ControlPlane   ControlPlane
	Spool          spool.Queue
	Logger         *slog.Logger
	DefaultTimeout time.Duration
	MaxResultBytes int64
	slots          chan struct{}
	wg             sync.WaitGroup
}

func New(max int) *Executor      { return &Executor{slots: make(chan struct{}, max)} }
func (e *Executor) Running() int { return len(e.slots) }
func (e *Executor) Wait()        { e.wg.Wait() }

func (e *Executor) Submit(parent context.Context, job jobs.Envelope) error {
	e.event(parent, "job.received", job, "")
	if err := e.Verifier.Verify(job); err != nil {
		e.event(parent, "job.rejected", job, err.Error())
		return err
	}
	m, ok := e.Registry.Get(job.ModuleID)
	if !ok {
		err := fmt.Errorf("%s: unknown module", jobs.ErrModuleUnavailable)
		e.event(parent, "job.rejected", job, err.Error())
		return err
	}
	d := m.Descriptor()
	if d.RiskClass != job.RiskClass {
		err := fmt.Errorf("%s: risk class mismatch", jobs.ErrInvalidJob)
		e.event(parent, "job.rejected", job, err.Error())
		return err
	}
	if d.RequiredCapability != "" && !e.Capabilities.Has(d.RequiredCapability) {
		err := fmt.Errorf("%s: %s", jobs.ErrCapabilityMissing, d.RequiredCapability)
		e.event(parent, "job.rejected", job, err.Error())
		return err
	}
	if err := m.Validate(job); err != nil {
		err = fmt.Errorf("%s: %w", jobs.ErrInvalidJob, err)
		e.event(parent, "job.rejected", job, err.Error())
		return err
	}
	select {
	case e.slots <- struct{}{}:
	default:
		return errors.New("no available execution slot")
	}
	e.wg.Add(1)
	go e.execute(parent, job, m)
	return nil
}
func (e *Executor) execute(parent context.Context, job jobs.Envelope, m modules.Module) {
	defer func() { <-e.slots; e.wg.Done() }()
	timeout := e.DefaultTimeout
	if remaining := time.Until(job.ExpiresAt); remaining < timeout {
		timeout = remaining
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(parent, timeout)
	ctx, cancel := context.WithCancel(timeoutCtx)
	defer timeoutCancel()
	defer cancel()
	go e.monitorCancellation(ctx, cancel, job.JobID)
	release, err := e.Registry.Acquire(ctx, job.ModuleID)
	if err != nil {
		e.finish(ctx, failed(job, err))
		return
	}
	defer release()
	cancelled, err := e.ControlPlane.IsCancelled(ctx, job.JobID)
	if err == nil && cancelled {
		e.finish(ctx, failedCode(job, "job cancelled", jobs.ErrInvalidJob))
		return
	}
	execJob := job
	cleanup := func() {}
	if strings.HasPrefix(job.ModuleID, "traffic.") || job.ModuleID == "security.suricata" {
		p, c, err := e.Artifacts.Download(ctx, job.Target)
		if err != nil {
			e.finish(ctx, failedCode(job, err.Error(), jobs.ErrArtifact))
			return
		}
		execJob.Target.ArtifactReference = p
		cleanup = c
	}
	defer cleanup()
	e.event(ctx, "job.started", job, "")
	result, runErr := m.Execute(ctx, execJob)
	if runErr != nil {
		code := jobs.ErrProcessFailed
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = jobs.ErrTimeout
		}
		result = failedCode(job, runErr.Error(), code)
	}
	result.JobID = job.JobID
	result.ModuleID = job.ModuleID
	if result.CompletedAt.IsZero() {
		result.CompletedAt = time.Now().UTC()
	}
	b, _ := json.Marshal(result)
	if int64(len(b)) > e.MaxResultBytes {
		result.Observations = nil
		result.Truncated = true
		result.Warnings = append(result.Warnings, "result exceeded limit; observations removed")
		result.ErrorCode = jobs.ErrOutputLimitExceeded
	}
	e.finish(context.WithoutCancel(parent), result)
}

func (e *Executor) monitorCancellation(ctx context.Context, cancel context.CancelFunc, jobID string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
			cancelled, err := e.ControlPlane.IsCancelled(checkCtx, jobID)
			checkCancel()
			if err == nil && cancelled {
				cancel()
				return
			}
		}
	}
}
func (e *Executor) finish(ctx context.Context, r jobs.ModuleResult) {
	if err := e.ControlPlane.ReportResult(ctx, r); err != nil {
		_ = e.Spool.Enqueue("result", r)
	}
	name := "job.completed"
	if r.Status != "COMPLETED" {
		name = "job.failed"
	}
	e.event(ctx, name, jobs.Envelope{JobID: r.JobID, ModuleID: r.ModuleID}, r.ErrorCode)
}
func (e *Executor) event(ctx context.Context, name string, j jobs.Envelope, message string) {
	ev := map[string]any{"type": name, "timestamp": time.Now().UTC(), "jobId": j.JobID, "moduleId": j.ModuleID, "message": message}
	if err := e.ControlPlane.ReportEvent(ctx, ev); err != nil {
		_ = e.Spool.Enqueue("event", ev)
	}
	e.Logger.Info(name, "jobId", j.JobID, "moduleId", j.ModuleID)
}
func failed(j jobs.Envelope, err error) jobs.ModuleResult {
	return failedCode(j, err.Error(), jobs.ErrProcessFailed)
}
func failedCode(j jobs.Envelope, msg, code string) jobs.ModuleResult {
	return jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, Status: "FAILED", StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC(), Summary: msg, ErrorCode: code}
}
