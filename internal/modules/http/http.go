package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"
)

type Module struct{}
type params struct {
	Method       string `json:"method"`
	MaxBodyBytes int64  `json:"maxBodyBytes"`
}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.http", Version: "1.0.0", RiskClass: jobs.RiskSafeActive, RequiredCapability: "HTTP", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	u, err := url.Parse(j.Target.URL)
	if err != nil || !(u.Scheme == "http" || u.Scheme == "https") || u.Host == "" || u.User != nil {
		return errors.New("absolute HTTP(S) URL without credentials required")
	}
	var p params
	if err = json.Unmarshal(j.Parameters, &p); err != nil {
		return err
	}
	if p.Method != "HEAD" && p.Method != "GET" {
		return errors.New("only HEAD and GET profiles are allowed")
	}
	if p.MaxBodyBytes < 0 || p.MaxBodyBytes > 1<<20 {
		return errors.New("body limit out of range")
	}
	return nil
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.Parameters, &p)
	limit := p.MaxBodyBytes
	if limit == 0 {
		limit = 64 << 10
	}
	origin, _ := url.Parse(j.Target.URL)
	tr := &nethttp.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	c := &nethttp.Client{Transport: tr, CheckRedirect: func(req *nethttp.Request, via []*nethttp.Request) error {
		if len(via) >= 3 {
			return errors.New("redirect limit reached")
		}
		if !strings.EqualFold(req.URL.Hostname(), origin.Hostname()) {
			return errors.New("cross-host redirect rejected")
		}
		return nil
	}}
	req, err := nethttp.NewRequestWithContext(ctx, p.Method, j.Target.URL, nil)
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	defer resp.Body.Close()
	n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "HTTP request completed", Metrics: map[string]float64{"statusCode": float64(resp.StatusCode), "bodyBytesRead": float64(n)}}
	if n > limit {
		r.Truncated = true
		r.Warnings = []string{"response body exceeded configured observation limit"}
	}
	return r, readErr
}
