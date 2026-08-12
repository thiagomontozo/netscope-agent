package executor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"github.com/thiagomontozo/netscope-agent/internal/spool"
)

type waitingModule struct{ executed *bool }

func (m waitingModule) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "mock.safe", Version: "1.0.0", RiskClass: jobs.RiskPassive, Implementation: "builtin", ConcurrencyLimit: 1}
}
func (m waitingModule) Validate(jobs.Envelope) error { return nil }
func (m waitingModule) Execute(ctx context.Context, _ jobs.Envelope) (jobs.ModuleResult, error) {
	*m.executed = true
	<-ctx.Done()
	return jobs.ModuleResult{}, ctx.Err()
}

type fakeControlPlane struct {
	mu           sync.Mutex
	cancellation bool
	failures     []protocol.JobFailure
	results      []protocol.JobResult
}

func (f *fakeControlPlane) StartJob(context.Context, string) error { return nil }
func (f *fakeControlPlane) ReportResult(_ context.Context, value protocol.JobResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, value)
	return nil
}
func (f *fakeControlPlane) ReportFailure(_ context.Context, value protocol.JobFailure) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, value)
	return nil
}

type successModule struct{}

func (successModule) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "mock.safe", Version: "1.0.0", RiskClass: jobs.RiskPassive, Implementation: "builtin", ConcurrencyLimit: 1}
}
func (successModule) Validate(jobs.Envelope) error { return nil }
func (successModule) Execute(_ context.Context, job jobs.Envelope) (jobs.ModuleResult, error) {
	now := time.Now().UTC()
	return jobs.ModuleResult{JobID: job.JobID, ModuleID: job.ModuleID, Status: "SUCCEEDED", StartedAt: now, CompletedAt: now, Summary: "synthetic success", Metrics: map[string]float64{}}, nil
}
func (f *fakeControlPlane) Cancellation(context.Context, string) (protocol.JobCancellation, error) {
	return protocol.JobCancellation{CancellationRequested: f.cancellation}, nil
}

func testUnsignedJob(timeout int) protocol.JobEnvelope {
	now := time.Now().UTC()
	return protocol.JobEnvelope{ProtocolVersion: "1.0", JobID: "33333333-3333-4333-8333-333333333333", OrganizationID: "22222222-2222-4222-8222-222222222222", AgentID: "11111111-1111-4111-8111-111111111111", ModuleID: "mock.safe", ModuleVersionRequirement: "1.0.0", ScopeID: "44444444-4444-4444-8444-444444444444", ScopeEnvironment: "INTERNAL", Target: protocol.JobTarget{Type: "HOSTNAME", Value: "fixture.test.invalid"}, ValidatedParameters: []byte(`{}`), RiskClass: protocol.RiskPassive, AuthorizationReference: "test-only", IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), TimeoutSeconds: timeout, Nonce: "dddddddddddddddddddddddddddddddd"}
}
func newTestExecutor(t *testing.T, cp *fakeControlPlane, module modules.Module) *Executor {
	t.Helper()
	registry, err := modules.NewRegistry(module)
	if err != nil {
		t.Fatal(err)
	}
	queue := &spool.Queue{Dir: t.TempDir(), MaxBytes: 1 << 20, MaxAge: time.Hour}
	e := New(1)
	e.Registry = registry
	e.Verifier = &security.JobVerifier{AgentID: "11111111-1111-4111-8111-111111111111", OrganizationID: "22222222-2222-4222-8222-222222222222"}
	e.ControlPlane = cp
	e.Spool = queue
	e.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	e.MaxResultBytes = 1 << 20
	return e
}

func TestCancellationDoesNotExecuteModule(t *testing.T) {
	executed := false
	cp := &fakeControlPlane{cancellation: true}
	e := newTestExecutor(t, cp, waitingModule{&executed})
	if err := e.Submit(context.Background(), testUnsignedJob(10)); err != nil {
		t.Fatal(err)
	}
	e.Wait()
	if executed {
		t.Fatal("cancelled module executed")
	}
	if len(cp.failures) != 1 || cp.failures[0].Code != protocol.FailureCancelled {
		t.Fatalf("failure=%v", cp.failures)
	}
}
func TestTimeoutCannotBecomeSucceeded(t *testing.T) {
	executed := false
	cp := &fakeControlPlane{}
	e := newTestExecutor(t, cp, waitingModule{&executed})
	if err := e.Submit(context.Background(), testUnsignedJob(1)); err != nil {
		t.Fatal(err)
	}
	e.Wait()
	if !executed {
		t.Fatal("mock module did not start")
	}
	if len(cp.failures) != 1 || cp.failures[0].Code != protocol.FailureTimeout {
		t.Fatalf("failure=%v", cp.failures)
	}
	if got := e.LastResult(); got == nil || got.Status != "TIMED_OUT" {
		t.Fatalf("last=%v", got)
	}
}

func TestSignedJobLogicalIntegration(t *testing.T) {
	job := testUnsignedJob(10)
	job.SigningKeyID = "test-only-2026-08"
	job.SignatureAlgorithm = security.SignatureAlgorithmEd25519
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	private := ed25519.NewKeyFromSeed(seed)
	payload, err := security.CanonicalJobPayload(job)
	if err != nil {
		t.Fatal(err)
	}
	job.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	cp := &fakeControlPlane{}
	e := newTestExecutor(t, cp, successModule{})
	e.Verifier.TrustedKeys = map[string]ed25519.PublicKey{job.SigningKeyID: private.Public().(ed25519.PublicKey)}
	e.Verifier.RequireSigned = true
	if err := e.Submit(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	e.Wait()
	if len(cp.results) != 1 || cp.results[0].Status != "SUCCEEDED" {
		t.Fatalf("results=%v", cp.results)
	}
	if len(cp.failures) != 0 {
		t.Fatalf("failures=%v", cp.failures)
	}
}
