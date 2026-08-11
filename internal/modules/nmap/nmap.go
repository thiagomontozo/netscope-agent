package nmap

import (
	"context"
	"encoding/xml"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"net"
	"time"
)

type Module struct {
	ID     string
	Runner nprocess.Runner
}

func NewDiscovery(r nprocess.Runner) Module { return Module{ID: "nmap.discovery", Runner: r} }
func NewServices(r nprocess.Runner) Module  { return Module{ID: "nmap.services", Runner: r} }
func (m Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: m.ID, Version: "0.1.0", RiskClass: jobs.RiskControlledActive, Implementation: "external-tool", RequiredTool: "nmap", RequiredCapability: "nmap", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 1}
}

type params struct {
	Profile  string `json:"profile"`
	MaxHosts int    `json:"maxHosts"`
}

func (m Module) Validate(j jobs.Envelope) error {
	if err := security.ValidateTarget(j.Target); err != nil {
		return err
	}
	if j.Target.Type != "HOSTNAME" && j.Target.Type != "IP" && j.Target.Type != "CIDR" {
		return errors.New("Nmap requires HOSTNAME, IP or CIDR target")
	}
	var p params
	if err := modules.DecodeParameters(j.ValidatedParameters, &p); err != nil {
		return err
	}
	maximum := 256
	if m.ID == "nmap.services" {
		maximum = 64
	}
	if p.MaxHosts < 1 || p.MaxHosts > maximum {
		return errors.New("maxHosts is outside the controlled profile")
	}
	if m.ID == "nmap.discovery" && p.Profile != "DISCOVERY" {
		return errors.New("discovery module requires DISCOVERY profile")
	}
	if m.ID == "nmap.services" && p.Profile != "COMMON_SERVICES" && p.Profile != "AUTHORIZED_SERVICE_INVENTORY" {
		return errors.New("service module profile is invalid")
	}
	if j.Target.Type == "CIDR" && !cidrWithinLimit(j.Target.Value, p.MaxHosts) {
		return errors.New("CIDR exceeds maxHosts")
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
	args := []string{"-sn", "-oX", "-", j.Target.Value}
	if m.ID == "nmap.services" {
		args = []string{"-sT", "--top-ports", "100", "--version-light", "-oX", "-", j.Target.Value}
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

func cidrWithinLimit(value string, maximum int) bool {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return false
	}
	ones, bits := network.Mask.Size()
	if ones < 0 || bits-ones >= 31 {
		return false
	}
	return 1<<(bits-ones) <= maximum
}
