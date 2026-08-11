package ping

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Module struct{ Runner nprocess.Runner }
type params struct {
	Count         int `json:"count"`
	TimeoutMillis int `json:"timeoutMillis"`
}

func New(r nprocess.Runner) Module { return Module{Runner: r} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.ping", Version: "1.0.0", RiskClass: jobs.RiskSafeActive, RequiredTool: "ping", RequiredCapability: "PING", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	if err := security.ValidateHost(j.Target.Host); err != nil {
		return err
	}
	var p params
	if err := json.Unmarshal(j.Parameters, &p); err != nil {
		return err
	}
	if p.Count < 1 || p.Count > 5 || p.TimeoutMillis < 100 || p.TimeoutMillis > 10000 {
		return errors.New("count or timeout outside safe profile")
	}
	return nil
}
func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.Parameters, &p)
	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", strconv.Itoa(p.Count), "-w", strconv.Itoa(p.TimeoutMillis), j.Target.Host}
	} else if runtime.GOOS == "darwin" {
		args = []string{"-c", strconv.Itoa(p.Count), "-W", strconv.Itoa(p.TimeoutMillis), j.Target.Host}
	} else {
		args = []string{"-c", strconv.Itoa(p.Count), "-W", strconv.Itoa((p.TimeoutMillis + 999) / 1000), j.Target.Host}
	}
	out, err := m.Runner.Run(ctx, "ping", args...)
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "Ping profile completed", Observations: []jobs.Observation{{Kind: "ping.output", Message: "Bounded tool output", Data: map[string]any{"output": strings.TrimSpace(string(out.Stdout))}}}, Truncated: out.StdoutTruncated || out.StderrTruncated}
	return r, err
}
