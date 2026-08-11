package tcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"net"
	"time"
)

type Module struct{}
type params struct {
	TimeoutMillis int `json:"timeoutMillis"`
}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.tcp", Version: "1.0.0", RiskClass: jobs.RiskSafeActive, RequiredCapability: "TCP", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 16}
}
func (Module) Validate(j jobs.Envelope) error {
	if j.Target.Host == "" || j.Target.Port < 1 || j.Target.Port > 65535 {
		return errors.New("valid host and port required")
	}
	var p params
	if len(j.Parameters) > 0 && json.Unmarshal(j.Parameters, &p) != nil {
		return errors.New("invalid parameters")
	}
	if p.TimeoutMillis < 0 || p.TimeoutMillis > 30000 {
		return errors.New("timeout out of range")
	}
	return nil
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.Parameters, &p)
	timeout := 5 * time.Second
	if p.TimeoutMillis > 0 {
		timeout = time.Duration(p.TimeoutMillis) * time.Millisecond
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.Target.Host, fmt.Sprint(j.Target.Port)))
	lat := time.Since(start)
	if c != nil {
		_ = c.Close()
	}
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "TCP connection succeeded", Metrics: map[string]float64{"connectMilliseconds": float64(lat.Milliseconds())}}
	return r, err
}
