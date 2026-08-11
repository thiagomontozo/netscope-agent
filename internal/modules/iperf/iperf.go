package iperf

import (
	"context"
	"errors"

	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
)

type Module struct{ Runner nprocess.Runner }
type params struct {
	DestinationEndpointID string `json:"destinationEndpointId"`
	DurationSeconds       int    `json:"durationSeconds"`
}

func New(r nprocess.Runner) Module { return Module{Runner: r} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "performance.iperf3", Version: "0.1.0", RiskClass: jobs.RiskControlledActive, Implementation: "external-tool", RequiredTool: "iperf3", RequiredCapability: "iperf3", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 1}
}
func (Module) Validate(job jobs.Envelope) error {
	var parameters params
	if err := modules.DecodeParameters(job.ValidatedParameters, &parameters); err != nil {
		return err
	}
	if parameters.DestinationEndpointID == "" || parameters.DurationSeconds < 1 || parameters.DurationSeconds > 30 {
		return errors.New("iperf3 controlled profile is invalid")
	}
	return errors.New("Protocol v1 does not convey the approved destination endpoint details")
}
func (Module) Execute(context.Context, jobs.Envelope) (jobs.ModuleResult, error) {
	return jobs.ModuleResult{}, errors.New("controlled endpoint details are unavailable")
}
