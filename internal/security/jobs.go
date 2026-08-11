package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/jobs"
)

type JobVerifier struct {
	AgentID   string
	PublicKey ed25519.PublicKey
	Now       func() time.Time
}

func LoadControlPlaneKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("NETSCOPE_CONTROL_PLANE_SIGNING_KEY is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("control plane key must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func (v JobVerifier) Verify(job jobs.Envelope) error {
	if job.ProtocolVersion != jobs.ProtocolVersion {
		return fmt.Errorf("%s: unsupported protocol version", jobs.ErrInvalidJob)
	}
	if job.JobID == "" || job.OrganizationID == "" || job.ModuleID == "" || job.Nonce == "" || job.Scope.ID == "" {
		return fmt.Errorf("%s: required field missing", jobs.ErrInvalidJob)
	}
	if job.AgentID != v.AgentID {
		return fmt.Errorf("%s: job belongs to another agent", jobs.ErrInvalidJob)
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if job.ExpiresAt.IsZero() || !job.ExpiresAt.After(now) {
		return fmt.Errorf("%s: job expired", jobs.ErrJobExpired)
	}
	if job.IssuedAt.IsZero() || job.IssuedAt.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("%s: invalid issue time", jobs.ErrInvalidJob)
	}
	if job.Target.Host == "" && job.Target.URL == "" && job.Target.ArtifactReference == "" {
		return fmt.Errorf("%s: target missing", jobs.ErrTargetRejected)
	}
	if job.RiskClass == jobs.RiskControlledActive && job.Scope.AuthorizationReference == "" {
		return fmt.Errorf("%s: controlled active job lacks authorization", jobs.ErrTargetRejected)
	}
	if job.RiskClass != jobs.RiskPassive && job.Scope.AuthorizationReference == "" {
		return fmt.Errorf("%s: active job lacks authorization", jobs.ErrTargetRejected)
	}
	if len(v.PublicKey) != ed25519.PublicKeySize || job.Signature == "" {
		return fmt.Errorf("%s: signed jobs are required", jobs.ErrInvalidJob)
	}
	sig, err := base64.RawURLEncoding.DecodeString(job.Signature)
	if err != nil {
		sig, err = base64.RawStdEncoding.DecodeString(job.Signature)
	}
	if err != nil {
		return fmt.Errorf("%s: malformed signature", jobs.ErrInvalidJob)
	}
	unsigned := job
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("%s: canonicalize envelope", jobs.ErrInvalidJob)
	}
	if !ed25519.Verify(v.PublicKey, payload, sig) {
		return fmt.Errorf("%s: signature verification failed", jobs.ErrInvalidJob)
	}
	return nil
}
