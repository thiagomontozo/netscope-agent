package zeek

import (
	"context"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"os"
	"path/filepath"
	"time"
)

type Module struct {
	Runner  nprocess.Runner
	DataDir string
}

func New(r nprocess.Runner, d string) Module { return Module{r, d} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "traffic.zeek", Version: "1.0.0", RiskClass: jobs.RiskPassive, RequiredTool: "zeek", RequiredCapability: "ZEEK", Platforms: []string{"linux", "darwin"}, ConcurrencyLimit: 1}
}
func (m Module) Validate(j jobs.Envelope) error {
	if len(j.Parameters) > 0 && string(j.Parameters) != "{}" && string(j.Parameters) != "null" {
		return errors.New("Zeek v0.1 accepts no parameters")
	}
	return security.ValidateTemporaryArtifact(m.DataDir, j.Target.ArtifactReference)
}
func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	dir, err := os.MkdirTemp(filepath.Join(m.DataDir, "temp"), "zeek-*")
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	defer os.RemoveAll(dir)
	out, err := m.Runner.RunInDir(ctx, dir, "zeek", "-r", j.Target.ArtifactReference)
	logs, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	names := make([]string, 0, len(logs))
	for _, p := range logs {
		names = append(names, filepath.Base(p))
	}
	return jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "Zeek offline PCAP analysis completed", Observations: []jobs.Observation{{Kind: "zeek.logs", Message: "Expected logs produced in isolated temporary directory", Data: map[string]any{"logs": names}}}, Truncated: out.StdoutTruncated || out.StderrTruncated}, err
}
