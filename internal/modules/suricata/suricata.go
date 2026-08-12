package suricata

import (
	"context"
	"errors"

	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
)

type Module struct {
	Runner  nprocess.ProcessRunner
	DataDir string
}
type params struct {
	ArtifactID string `json:"artifactId"`
	Preset     string `json:"preset"`
}

func New(r nprocess.ProcessRunner, dataDir string) Module { return Module{Runner: r, DataDir: dataDir} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "security.suricata", Version: "0.1.0", RiskClass: jobs.RiskPassive, Implementation: "external-tool", RequiredTool: "suricata", RequiredCapability: "suricata", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 1}
}
func (Module) Validate(job jobs.Envelope) error {
	var parameters params
	if err := modules.DecodeParameters(job.ValidatedParameters, &parameters); err != nil {
		return err
	}
	if parameters.ArtifactID == "" || (parameters.Preset != "METADATA" && parameters.Preset != "PROTOCOL_SUMMARY" && parameters.Preset != "EVE_IMPORT") {
		return errors.New("Suricata artifact or preset is invalid")
	}
	return errors.New("Protocol v1 does not define authorized artifact content delivery")
}
func (Module) Execute(context.Context, jobs.Envelope) (jobs.ModuleResult, error) {
	return jobs.ModuleResult{}, errors.New("artifact content is unavailable")
}
