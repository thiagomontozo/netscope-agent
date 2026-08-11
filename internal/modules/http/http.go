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
	Method           string `json:"method"`
	RedirectLimit    int    `json:"redirectLimit"`
	ExpectedStatus   int    `json:"expectedStatus"`
	MaxResponseBytes int64  `json:"maxResponseBytes"`
}

func New() Module { return Module{} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "network.http", Version: "0.1.0", RiskClass: jobs.RiskSafeActive, Implementation: "builtin", RequiredCapability: "http", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 8}
}
func (Module) Validate(j jobs.Envelope) error {
	if j.Target.Type != "URL" {
		return errors.New("HTTP module requires a URL target")
	}
	u, err := url.Parse(j.Target.Value)
	if err != nil || !(u.Scheme == "http" || u.Scheme == "https") || u.Host == "" || u.User != nil {
		return errors.New("absolute HTTP(S) URL without credentials required")
	}
	var p params
	if err = modules.DecodeParameters(j.ValidatedParameters, &p); err != nil {
		return err
	}
	if p.Method != "HEAD" && p.Method != "GET" {
		return errors.New("only HEAD and GET profiles are allowed")
	}
	if p.RedirectLimit < 0 || p.RedirectLimit > 5 || p.ExpectedStatus < 100 || p.ExpectedStatus > 599 || p.MaxResponseBytes < 0 || p.MaxResponseBytes > 1<<20 {
		return errors.New("HTTP profile limits are invalid")
	}
	return nil
}
func (Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	var p params
	_ = json.Unmarshal(j.ValidatedParameters, &p)
	limit := p.MaxResponseBytes
	origin, _ := url.Parse(j.Target.Value)
	tr := &nethttp.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	c := &nethttp.Client{Transport: tr, CheckRedirect: func(req *nethttp.Request, via []*nethttp.Request) error {
		if len(via) > p.RedirectLimit {
			return errors.New("redirect limit reached")
		}
		if !strings.EqualFold(req.URL.Hostname(), origin.Hostname()) {
			return errors.New("cross-host redirect rejected")
		}
		return nil
	}}
	req, err := nethttp.NewRequestWithContext(ctx, p.Method, j.Target.Value, nil)
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	defer resp.Body.Close()
	n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
	r := jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "HTTP request completed", Metrics: map[string]float64{"HTTP_STATUS": float64(resp.StatusCode), "HTTP_DURATION_MS": float64(time.Since(start).Milliseconds())}, Observations: []jobs.Observation{{Kind: "http.transaction", Message: "Bounded HTTP transaction metadata", Data: map[string]any{"statusCode": resp.StatusCode, "expectedStatus": p.ExpectedStatus, "tls": origin.Scheme == "https", "contentType": resp.Header.Get("Content-Type"), "contentLength": resp.ContentLength, "bytesRead": n}}}}
	if n > limit {
		r.Truncated = true
		r.Warnings = []string{"response body exceeded configured observation limit"}
	}
	return r, readErr
}
