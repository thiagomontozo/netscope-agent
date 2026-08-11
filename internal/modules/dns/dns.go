package dns

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
)

type Module struct{}
type params struct {
	Type string `json:"type"`
}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.dns", Version: "1.0.0", RiskClass: jobs.RiskSafeActive, RequiredCapability: "DNS", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	var p params
	if err := json.Unmarshal(j.Parameters, &p); err != nil {
		return err
	}
	switch strings.ToUpper(p.Type) {
	case "A", "AAAA", "CNAME", "MX", "NS", "TXT":
	default:
		return errors.New("unsupported DNS record type")
	}
	if net.ParseIP(j.Target.Host) == nil && strings.TrimSpace(j.Target.Host) == "" {
		return errors.New("host required")
	}
	return nil
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.Parameters, &p)
	r := net.DefaultResolver
	var vals []string
	var err error
	switch strings.ToUpper(p.Type) {
	case "A", "AAAA":
		var ips []net.IPAddr
		ips, err = r.LookupIPAddr(ctx, j.Target.Host)
		for _, ip := range ips {
			if (strings.ToUpper(p.Type) == "A") == (ip.IP.To4() != nil) {
				vals = append(vals, ip.IP.String())
			}
		}
	case "CNAME":
		var v string
		v, err = r.LookupCNAME(ctx, j.Target.Host)
		vals = []string{v}
	case "MX":
		var v []*net.MX
		v, err = r.LookupMX(ctx, j.Target.Host)
		for _, x := range v {
			vals = append(vals, x.Host)
		}
	case "NS":
		var v []*net.NS
		v, err = r.LookupNS(ctx, j.Target.Host)
		for _, x := range v {
			vals = append(vals, x.Host)
		}
	case "TXT":
		vals, err = r.LookupTXT(ctx, j.Target.Host)
	}
	res := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "DNS lookup completed", Observations: []jobs.Observation{{Kind: "dns.records", Message: "Validated DNS response", Data: map[string]any{"type": strings.ToUpper(p.Type), "records": vals}}}}
	return res, err
}
