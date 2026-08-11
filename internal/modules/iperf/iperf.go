package iperf

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"strconv"
	"time"
)

type Module struct{ Runner nprocess.Runner }
type params struct {
	DurationSeconds int    `json:"durationSeconds"`
	Protocol        string `json:"protocol"`
}

func New(r nprocess.Runner) Module { return Module{r} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "performance.iperf3", Version: "1.0.0", RiskClass: jobs.RiskControlledActive, RequiredTool: "iperf3", RequiredCapability: "IPERF3", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 1}
}
func (Module) Validate(j jobs.Envelope) error {
	if err := security.ValidateHost(j.Target.Host); err != nil {
		return err
	}
	if !j.Target.ControlledEndpoint || j.Scope.AuthorizationReference == "" {
		return errors.New("iperf3 requires an authorized CONTROLLED_ENDPOINT")
	}
	if j.Target.Port < 1 || j.Target.Port > 65535 {
		return errors.New("valid port required")
	}
	var p params
	if err := json.Unmarshal(j.Parameters, &p); err != nil {
		return err
	}
	if p.DurationSeconds < 1 || p.DurationSeconds > 30 {
		return errors.New("duration outside safe profile")
	}
	if p.Protocol != "tcp" && p.Protocol != "udp" {
		return errors.New("protocol must be tcp or udp")
	}
	return nil
}
func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.Parameters, &p)
	args := []string{"-c", j.Target.Host, "-p", strconv.Itoa(j.Target.Port), "-t", strconv.Itoa(p.DurationSeconds), "-J"}
	if p.Protocol == "udp" {
		args = append(args, "-u", "-b", "1M")
	}
	out, err := m.Runner.Run(ctx, "iperf3", args...)
	return jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "iperf3 controlled endpoint profile completed", Observations: []jobs.Observation{{Kind: "iperf3.json", Message: "Bounded JSON tool output", Data: map[string]any{"output": string(out.Stdout)}}}, Truncated: out.StdoutTruncated || out.StderrTruncated}, err
}
