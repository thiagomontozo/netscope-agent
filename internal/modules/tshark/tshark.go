package tshark

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"time"
)

type Module struct {
	Runner  nprocess.Runner
	DataDir string
}
type params struct {
	Profile string `json:"profile"`
}

func New(r nprocess.Runner, d string) Module { return Module{r, d} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "traffic.tshark", Version: "1.0.0", RiskClass: jobs.RiskPassive, RequiredTool: "tshark", RequiredCapability: "TSHARK", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 1}
}
func (m Module) Validate(j jobs.Envelope) error {
	if err := security.ValidateTemporaryArtifact(m.DataDir, j.Target.ArtifactReference); err != nil {
		return err
	}
	var p params
	if err := json.Unmarshal(j.Parameters, &p); err != nil {
		return err
	}
	switch p.Profile {
	case "summary", "protocol_distribution", "selected_fields":
		return nil
	}
	return errors.New("unsupported TShark profile")
}
func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.Parameters, &p)
	args := []string{"-r", j.Target.ArtifactReference, "-q", "-z", "io,phs"}
	if p.Profile == "summary" {
		args = []string{"-r", j.Target.ArtifactReference, "-q", "-z", "io,stat,0"}
	} else if p.Profile == "selected_fields" {
		args = []string{"-r", j.Target.ArtifactReference, "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol"}
	}
	out, err := m.Runner.Run(ctx, "tshark", args...)
	return jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "TShark offline PCAP profile completed", Observations: []jobs.Observation{{Kind: "tshark.profile", Message: "Bounded offline analysis", Data: map[string]any{"profile": p.Profile, "output": string(out.Stdout)}}}, Truncated: out.StdoutTruncated || out.StderrTruncated}, err
}
