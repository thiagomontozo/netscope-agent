package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/identity"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
)

const maxResponseBytes int64 = 4 << 20

type Client struct {
	base     *url.URL
	http     *http.Client
	version  string
	identity *identity.Identity
}

func New(rawURL string, h *http.Client, version string, id *identity.Identity) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return &Client{base: u, http: h, version: version, identity: id}, nil
}
func (c *Client) CloseIdleConnections()       { c.http.CloseIdleConnections() }
func (c *Client) endpoint(path string) string { return strings.TrimRight(c.base.String(), "/") + path }

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any, enrollmentToken string) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NetScope-Agent/"+c.version)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if enrollmentToken != "" {
		req.Header.Set("Authorization", "Enrollment "+enrollmentToken)
	} else if c.identity != nil && c.identity.Credential != "" {
		req.Header.Set("Authorization", c.identity.Authorization())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxResponseBytes {
		return errors.New("control plane response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(out); err != nil {
			return fmt.Errorf("decode control plane response: %w", err)
		}
	}
	return nil
}

type EnrollRequest struct{ Name, PublicKey, OS, Architecture, Version string }
type EnrollResponse struct {
	AgentID                string `json:"agentId"`
	Credential             string `json:"credential"`
	ControlPlaneSigningKey string `json:"controlPlaneSigningKey,omitempty"`
}

func (c *Client) Enroll(ctx context.Context, token string, req EnrollRequest) (EnrollResponse, error) {
	var out EnrollResponse
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/enroll", req, &out, token)
	return out, err
}
func (c *Client) NextJob(ctx context.Context) (*jobs.Envelope, error) {
	var out struct {
		Job *jobs.Envelope `json:"job"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/agent/v1/jobs/next", nil, &out, "")
	return out.Job, err
}
func (c *Client) ReportResult(ctx context.Context, result jobs.ModuleResult) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/jobs/"+url.PathEscape(result.JobID)+"/result", result, nil, "")
}
func (c *Client) ReportEvent(ctx context.Context, event any) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/events", event, nil, "")
}
func (c *Client) Heartbeat(ctx context.Context, heartbeat any) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/heartbeat", heartbeat, nil, "")
}
func (c *Client) ReportCapabilities(ctx context.Context, report any) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/capabilities", report, nil, "")
}
func (c *Client) IsCancelled(ctx context.Context, jobID string) (bool, error) {
	var out struct {
		Cancelled bool `json:"cancelled"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/agent/v1/jobs/"+url.PathEscape(jobID)+"/cancellation", nil, &out, "")
	return out.Cancelled, err
}
func (c *Client) Send(ctx context.Context, kind string, payload json.RawMessage) error {
	var v any
	if err := json.Unmarshal(payload, &v); err != nil {
		return err
	}
	if kind == "result" {
		var r jobs.ModuleResult
		if err := json.Unmarshal(payload, &r); err != nil {
			return err
		}
		return c.ReportResult(ctx, r)
	}
	return c.ReportEvent(ctx, v)
}

func Backoff(attempt int, maximum time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 8 {
		attempt = 8
	}
	d := time.Second * time.Duration(1<<attempt)
	if d > maximum {
		d = maximum
	}
	jitter := time.Duration(rand.Int64N(int64(d/3) + 1))
	return d + jitter
}
