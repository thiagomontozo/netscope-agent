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
	Samples   int `json:"samples"`
	TimeoutMS int `json:"timeoutMs"`
}

func New(r nprocess.Runner) Module { return Module{Runner: r} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.ping", Version: "0.1.0", RiskClass: jobs.RiskSafeActive, Implementation: "external-tool", RequiredTool: "ping", RequiredCapability: "ping", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	if _, err := security.Host(j.Target); err != nil {
		return err
	}
	var p params
	if err := modules.DecodeParameters(j.ValidatedParameters, &p); err != nil {
		return err
	}
	if p.Samples < 1 || p.Samples > 10 || p.TimeoutMS < 100 || p.TimeoutMS > 10000 {
		return errors.New("count or timeout outside safe profile")
	}
	return nil
}
func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.ValidatedParameters, &p)
	host, _ := security.Host(j.Target)
	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", strconv.Itoa(p.Samples), "-w", strconv.Itoa(p.TimeoutMS), host}
	} else if runtime.GOOS == "darwin" {
		args = []string{"-c", strconv.Itoa(p.Samples), "-W", strconv.Itoa(p.TimeoutMS), host}
	} else {
		args = []string{"-c", strconv.Itoa(p.Samples), "-W", strconv.Itoa((p.TimeoutMS + 999) / 1000), host}
	}
	out, err := m.Runner.Run(ctx, "ping", args...)
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "Ping profile completed", Observations: []jobs.Observation{{Kind: "ping.output", Message: "Bounded tool output", Data: map[string]any{"output": strings.TrimSpace(string(out.Stdout))}}}, Truncated: out.StdoutTruncated || out.StderrTruncated}
	return r, err
}
