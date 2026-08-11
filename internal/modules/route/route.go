package route

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
	MaxHops int `json:"maxHops"`
}
type hop struct {
	Hop       int      `json:"hop"`
	Address   string   `json:"address,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	Latencies []string `json:"latencies,omitempty"`
	Timeout   bool     `json:"timeout"`
}

func New(r nprocess.Runner) Module { return Module{Runner: r} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.route", Version: "1.0.0", RiskClass: jobs.RiskSafeActive, RequiredCapability: "TRACEROUTE", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 2}
}
func (Module) Validate(j jobs.Envelope) error {
	if err := security.ValidateHost(j.Target.Host); err != nil {
		return err
	}
	var p params
	if err := json.Unmarshal(j.Parameters, &p); err != nil {
		return err
	}
	if p.MaxHops < 1 || p.MaxHops > 30 {
		return errors.New("maxHops outside safe profile")
	}
	return nil
}
func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.Parameters, &p)
	binary := "traceroute"
	args := []string{"-m", strconv.Itoa(p.MaxHops), "-n", j.Target.Host}
	if runtime.GOOS == "windows" {
		binary = "tracert"
		args = []string{"-h", strconv.Itoa(p.MaxHops), "-d", j.Target.Host}
	}
	out, err := m.Runner.Run(ctx, binary, args...)
	hops := normalize(string(out.Stdout))
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "Route trace profile completed", Observations: []jobs.Observation{{Kind: "route.raw_bounded", Message: "Adapter output for normalized route processing", Data: map[string]any{"output": strings.TrimSpace(string(out.Stdout))}}}, Truncated: out.StdoutTruncated || out.StderrTruncated}
	r.Observations = []jobs.Observation{{Kind: "route.hops", Message: "Normalized route hops", Data: map[string]any{"hops": hops}}}
	return r, err
}

func normalize(output string) []hop {
	var result []hop
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil || n < 1 || n > 255 {
			continue
		}
		h := hop{Hop: n}
		for i, field := range fields[1:] {
			if field == "*" {
				h.Timeout = true
				continue
			}
			if strings.HasSuffix(field, "ms") || (i+2 < len(fields) && fields[i+2] == "ms") {
				h.Latencies = append(h.Latencies, field)
				continue
			}
			candidate := strings.Trim(field, "()[]")
			if security.ValidateHost(candidate) == nil {
				if strings.ContainsAny(candidate, ":0123456789") {
					h.Address = candidate
				} else if h.Hostname == "" {
					h.Hostname = candidate
				}
			}
		}
		result = append(result, h)
	}
	return result
}
