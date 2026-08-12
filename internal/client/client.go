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
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

const maxResponseBytes int64 = 4 << 20

type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("control plane %s (HTTP %d, request %s)", e.Code, e.StatusCode, e.RequestID)
	}
	return fmt.Sprintf("control plane returned HTTP %d", e.StatusCode)
}

func IsTerminal(err error) bool {
	var api *APIError
	return errors.As(err, &api) && (api.Code == "AGENT_REVOKED" || api.Code == "PROTOCOL_INCOMPATIBLE")
}

type Client struct {
	base    *url.URL
	http    *http.Client
	version string
}

func New(rawURL string, h *http.Client, version string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("control plane URL must be absolute HTTPS")
	}
	return &Client{base: u, http: h, version: version}, nil
}

func (c *Client) CloseIdleConnections()       { c.http.CloseIdleConnections() }
func (c *Client) endpoint(path string) string { return strings.TrimRight(c.base.String(), "/") + path }

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
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
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxResponseBytes {
		return errors.New("control plane response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		var envelope protocol.ErrorEnvelope
		if json.Unmarshal(data, &envelope) == nil {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
			apiErr.RequestID = envelope.Error.RequestID
		}
		return apiErr
	}
	if out != nil && len(data) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(out); err != nil {
			return fmt.Errorf("decode control plane response: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return errors.New("control plane response contains multiple JSON values")
		}
	}
	return nil
}

func (c *Client) Enroll(ctx context.Context, request protocol.EnrollmentRequest) (protocol.EnrollmentResponse, error) {
	var envelope protocol.DataEnvelope[protocol.EnrollmentResponse]
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/enroll", request, &envelope)
	return envelope.Data, err
}

func (c *Client) Heartbeat(ctx context.Context, heartbeat protocol.Heartbeat) (protocol.HeartbeatResponse, error) {
	var envelope protocol.DataEnvelope[protocol.HeartbeatResponse]
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/heartbeat", heartbeat, &envelope)
	return envelope.Data, err
}

func (c *Client) ReportCapabilities(ctx context.Context, report protocol.CapabilityManifest) (protocol.CapabilityResponse, error) {
	var envelope protocol.DataEnvelope[protocol.CapabilityResponse]
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/capabilities", report, &envelope)
	return envelope.Data, err
}

func (c *Client) NextJob(ctx context.Context) (*protocol.JobEnvelope, error) {
	var envelope protocol.DataEnvelope[*protocol.JobEnvelope]
	if err := c.doJSON(ctx, http.MethodGet, "/agent/v1/jobs/next", nil, &envelope); err != nil {
		return nil, err
	}
	return envelope.Data, nil
}

func (c *Client) StartJob(ctx context.Context, jobID string) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/jobs/"+url.PathEscape(jobID)+"/start", nil, nil)
}

func (c *Client) ReportResult(ctx context.Context, result protocol.JobResult) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/jobs/"+url.PathEscape(result.JobID)+"/result", result, nil)
}

func (c *Client) ReportFailure(ctx context.Context, failure protocol.JobFailure) error {
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/jobs/"+url.PathEscape(failure.JobID)+"/fail", failure, nil)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Code == "JOB_STATE_INVALID" {
		// The failure endpoint is state-machine guarded rather than receipt based.
		// A retry after an ambiguous response can observe the terminal state.
		return nil
	}
	return err
}

func (c *Client) ReportEvidence(ctx context.Context, evidence protocol.EvidenceRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/evidence", evidence, nil)
}

func (c *Client) Cancellation(ctx context.Context, jobID string) (protocol.JobCancellation, error) {
	var envelope protocol.DataEnvelope[protocol.JobCancellation]
	err := c.doJSON(ctx, http.MethodGet, "/agent/v1/jobs/"+url.PathEscape(jobID)+"/cancellation", nil, &envelope)
	return envelope.Data, err
}

func (c *Client) RotateIdentity(ctx context.Context, csrPEM string) (identity.RotationResponse, error) {
	var envelope protocol.DataEnvelope[identity.RotationResponse]
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/identity/rotate", map[string]string{"csrPem": csrPEM}, &envelope)
	return envelope.Data, err
}

func (c *Client) ConfirmIdentityRotation(ctx context.Context, certificateID string) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/identity/rotate/confirm", map[string]string{"certificateId": certificateID}, nil)
}

func (c *Client) RollbackIdentityRotation(ctx context.Context, certificateID string) error {
	return c.doJSON(ctx, http.MethodPost, "/agent/v1/identity/rotate/rollback", map[string]string{"certificateId": certificateID}, nil)
}

func (c *Client) AuthorizeArtifact(ctx context.Context, artifactID, jobID, purpose string) (protocol.ArtifactAuthorization, error) {
	var envelope protocol.DataEnvelope[protocol.ArtifactAuthorization]
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/artifacts/"+url.PathEscape(artifactID)+"/authorize", map[string]string{"jobId": jobID, "purpose": purpose}, &envelope)
	return envelope.Data, err
}

func (c *Client) CreateArtifact(ctx context.Context, manifest protocol.ArtifactManifest) (protocol.ArtifactManifest, error) {
	var envelope protocol.DataEnvelope[protocol.ArtifactManifest]
	err := c.doJSON(ctx, http.MethodPost, "/agent/v1/artifacts", manifest, &envelope)
	return envelope.Data, err
}

func (c *Client) Send(ctx context.Context, kind string, payload json.RawMessage) error {
	switch kind {
	case "result":
		var result protocol.JobResult
		if err := json.Unmarshal(payload, &result); err != nil {
			return err
		}
		return c.ReportResult(ctx, result)
	case "failure":
		var failure protocol.JobFailure
		if err := json.Unmarshal(payload, &failure); err != nil {
			return err
		}
		return c.ReportFailure(ctx, failure)
	case "evidence":
		var evidence protocol.EvidenceRequest
		if err := json.Unmarshal(payload, &evidence); err != nil {
			return err
		}
		return c.ReportEvidence(ctx, evidence)
	default:
		return errors.New("unsupported spool item kind")
	}
}

func Backoff(attempt int, maximum time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 8 {
		attempt = 8
	}
	delay := time.Second * time.Duration(1<<attempt)
	if delay > maximum {
		delay = maximum
	}
	jitter := time.Duration(rand.Int64N(int64(delay/3) + 1))
	return delay + jitter
}
