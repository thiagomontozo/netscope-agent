package tls

import (
	"context"
	ctls "crypto/tls"
	"errors"
	"fmt"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"net"
	"time"
)

type Module struct{}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.tls", Version: "1.0.0", RiskClass: jobs.RiskSafeActive, RequiredCapability: "TLS", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	if j.Target.Host == "" || j.Target.Port < 1 || j.Target.Port > 65535 {
		return errors.New("valid host and port required")
	}
	return nil
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.Target.Host, fmt.Sprint(j.Target.Port)))
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	defer raw.Close()
	c := ctls.Client(raw, &ctls.Config{ServerName: j.Target.Host, MinVersion: ctls.VersionTLS12})
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
	}
	return jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "TLS handshake completed", Observations: []jobs.Observation{{Kind: "tls.connection", Message: "Validated TLS connection", Data: data}}}, nil
}
