package tcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"net"
	"time"
)

type Module struct{}
type params struct {
	Port      int `json:"port"`
	TimeoutMS int `json:"timeoutMs"`
}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.tcp", Version: "0.1.0", RiskClass: jobs.RiskSafeActive, Implementation: "builtin", RequiredCapability: "tcp", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 16}
}
func (Module) Validate(j jobs.Envelope) error {
	if _, err := security.Host(j.Target); err != nil {
		return err
	}
	var p params
	if err := modules.DecodeParameters(j.ValidatedParameters, &p); err != nil {
		return err
	}
	if p.Port < 1 || p.Port > 65535 || p.TimeoutMS < 100 || p.TimeoutMS > 10000 {
		return errors.New("port or timeout out of range")
	}
	return nil
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.ValidatedParameters, &p)
	host, _ := security.Host(j.Target)
	timeout := time.Duration(p.TimeoutMS) * time.Millisecond
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(p.Port)))
	lat := time.Since(start)
	if c != nil {
		_ = c.Close()
	}
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "TCP connection succeeded", Metrics: map[string]float64{"TCP_CONNECT_DURATION_MS": float64(lat.Milliseconds()), "AVAILABILITY": 1}}
	return r, err
}
