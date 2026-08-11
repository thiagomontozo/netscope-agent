package tls

import (
	"context"
	ctls "crypto/tls"
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
	Port              int `json:"port"`
	ExpiryWarningDays int `json:"expiryWarningDays"`
}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.tls", Version: "0.1.0", RiskClass: jobs.RiskSafeActive, Implementation: "builtin", RequiredCapability: "tls", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	if _, err := security.Host(j.Target); err != nil {
		return err
	}
	var p params
	if err := modules.DecodeParameters(j.ValidatedParameters, &p); err != nil {
		return err
	}
	if p.Port < 1 || p.Port > 65535 || p.ExpiryWarningDays < 1 || p.ExpiryWarningDays > 365 {
		return errors.New("TLS port or expiry threshold is invalid")
	}
	return nil
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.ValidatedParameters, &p)
	host, _ := security.Host(j.Target)
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(p.Port)))
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	defer raw.Close()
	c := ctls.Client(raw, &ctls.Config{ServerName: host, MinVersion: ctls.VersionTLS12})
	if err = c.HandshakeContext(ctx); err != nil {
		return jobs.ModuleResult{}, err
	}
	s := c.ConnectionState()
	data := map[string]any{"protocol": ctls.VersionName(s.Version), "cipherSuite": ctls.CipherSuiteName(s.CipherSuite), "hostnameValidated": true}
	if len(s.PeerCertificates) > 0 {
		x := s.PeerCertificates[0]
		data["subject"] = x.Subject.String()
		data["issuer"] = x.Issuer.String()
		data["notBefore"] = x.NotBefore
		data["notAfter"] = x.NotAfter
		data["dnsNames"] = x.DNSNames
		data["daysUntilExpiration"] = int(time.Until(x.NotAfter).Hours() / 24)
	}
	result := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "TLS handshake completed", Observations: []jobs.Observation{{Kind: "tls.connection", Message: "Validated TLS connection", Data: data}}}
	if len(s.PeerCertificates) > 0 {
		result.Metrics = map[string]float64{"TLS_DAYS_UNTIL_EXPIRATION": time.Until(s.PeerCertificates[0].NotAfter).Hours() / 24}
	}
	return result, nil
}
