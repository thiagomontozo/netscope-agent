package nmap

import (
	"context"
	"encoding/xml"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"strings"
	"time"
)

type Module struct {
	ID     string
	Runner nprocess.Runner
}

func NewDiscovery(r nprocess.Runner) Module { return Module{ID: "nmap.discovery", Runner: r} }
func NewServices(r nprocess.Runner) Module  { return Module{ID: "nmap.services", Runner: r} }
func (m Module) Descriptor() modules.Descriptor {
	risk := jobs.RiskSafeActive
	if m.ID == "nmap.services" {
		risk = jobs.RiskControlledActive
	}
	return modules.Descriptor{ID: m.ID, Version: "1.0.0", RiskClass: risk, RequiredTool: "nmap", RequiredCapability: "NMAP", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 1}
}
func (m Module) Validate(j jobs.Envelope) error {
	if err := security.ValidateHost(j.Target.Host); err != nil {
		return err
	}
	if len(strings.TrimSpace(string(j.Parameters))) > 2 {
		return errors.New("nmap profiles do not accept parameters")
	}
	if m.ID == "nmap.services" && (!j.Target.ControlledEndpoint || j.Scope.AuthorizationReference == "") {
		return errors.New("services profile requires authorized controlled endpoint")
	}
	return nil
}

type run struct {
	Hosts []struct {
		Address []struct {
			Addr string `xml:"addr,attr"`
		} `xml:"address"`
		Ports []struct {
			PortID   int    `xml:"portid,attr"`
			Protocol string `xml:"protocol,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	args := []string{"-sn", "-oX", "-", j.Target.Host}
	if m.ID == "nmap.services" {
		args = []string{"-sT", "--top-ports", "100", "--version-light", "-oX", "-", j.Target.Host}
	}
	out, err := m.Runner.Run(ctx, "nmap", args...)
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "Nmap fixed profile completed", Truncated: out.StdoutTruncated || out.StderrTruncated}
	if err != nil {
		return r, err
	}
	var parsed run
	if err := xml.Unmarshal(out.Stdout, &parsed); err != nil {
		return r, errors.New("invalid bounded Nmap XML output")
	}
	r.Observations = []jobs.Observation{{Kind: "nmap.xml", Message: "Parsed structured Nmap result", Data: map[string]any{"hosts": parsed.Hosts}}}
	return r, nil
}
