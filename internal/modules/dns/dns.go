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
	"github.com/thiagomontozo/netscope-agent/internal/security"
)

type Module struct{}
type params struct {
	RecordType string `json:"recordType"`
}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.dns", Version: "0.1.0", RiskClass: jobs.RiskSafeActive, Implementation: "builtin", RequiredCapability: "dns", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	var p params
	if err := modules.DecodeParameters(j.ValidatedParameters, &p); err != nil {
		return err
	}
	switch strings.ToUpper(p.RecordType) {
	case "A", "AAAA", "CNAME", "MX", "NS", "TXT":
	default:
		return errors.New("unsupported DNS record type")
	}
	_, err := security.Host(j.Target)
	return err
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.ValidatedParameters, &p)
	host, _ := security.Host(j.Target)
	r := net.DefaultResolver
	var vals []string
	var err error
	switch strings.ToUpper(p.RecordType) {
	case "A", "AAAA":
		var ips []net.IPAddr
		ips, err = r.LookupIPAddr(ctx, host)
		for _, ip := range ips {
			if (strings.ToUpper(p.RecordType) == "A") == (ip.IP.To4() != nil) {
				vals = append(vals, ip.IP.String())
			}
		}
	case "CNAME":
		var v string
		v, err = r.LookupCNAME(ctx, host)
		vals = []string{v}
	case "MX":
		var v []*net.MX
		v, err = r.LookupMX(ctx, host)
		for _, x := range v {
			vals = append(vals, x.Host)
		}
	case "NS":
		var v []*net.NS
		v, err = r.LookupNS(ctx, host)
		for _, x := range v {
			vals = append(vals, x.Host)
		}
	case "TXT":
		vals, err = r.LookupTXT(ctx, host)
	}
	duration := float64(time.Since(start).Milliseconds())
	res := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "DNS lookup completed", Observations: []jobs.Observation{{Kind: "dns.records", Message: "Validated DNS response", Data: map[string]any{"recordType": strings.ToUpper(p.RecordType), "records": vals}}}, Metrics: map[string]float64{"DNS_DURATION_MS": duration}}
	return res, err
}
