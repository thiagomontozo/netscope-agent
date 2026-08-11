package security

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

var (
	uuidPattern   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	noncePattern  = regexp.MustCompile(`^[a-f0-9]{32,128}$`)
	modulePattern = regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)+$`)
)

type VerificationError struct {
	Code protocol.FailureCode
	Err  error
}

func (e *VerificationError) Error() string { return e.Err.Error() }
func (e *VerificationError) Unwrap() error { return e.Err }

func FailureCode(err error) protocol.FailureCode {
	var verification *VerificationError
	if errors.As(err, &verification) {
		return verification.Code
	}
	return protocol.FailureInvalidJob
}

type JobVerifier struct {
	AgentID        string
	OrganizationID string
	Now            func() time.Time
	mu             sync.Mutex
	seen           map[string]time.Time
}

func (v *JobVerifier) Verify(job protocol.JobEnvelope) error {
	fail := func(code protocol.FailureCode, message string) error {
		return &VerificationError{Code: code, Err: errors.New(message)}
	}
	if protocol.RequireCompatible(job.ProtocolVersion) != nil {
		return fail(protocol.FailureProtocol, "job protocol major version is incompatible")
	}
	if !uuidPattern.MatchString(job.JobID) || !uuidPattern.MatchString(job.AgentID) || !uuidPattern.MatchString(job.OrganizationID) || !uuidPattern.MatchString(job.ScopeID) || !modulePattern.MatchString(job.ModuleID) {
		return fail(protocol.FailureInvalidJob, "job identity fields are invalid")
	}
	for _, optionalID := range []*string{job.AssetID, job.ServiceID, job.DiagnosticRunID, job.VantagePointID} {
		if optionalID != nil && !uuidPattern.MatchString(*optionalID) {
			return fail(protocol.FailureInvalidJob, "job contains an invalid optional identity")
		}
	}
	if job.AgentID != v.AgentID || job.OrganizationID != v.OrganizationID {
		return fail(protocol.FailureInvalidJob, "job belongs to another agent or organization")
	}
	if job.ModuleVersionRequirement == "" || job.AuthorizationReference == "" || len(job.AuthorizationReference) > 500 || len(job.ValidatedParameters) == 0 || !noncePattern.MatchString(job.Nonce) {
		return fail(protocol.FailureInvalidJob, "job required fields are missing")
	}
	if job.ScopeEnvironment != "INTERNAL" && job.ScopeEnvironment != "PUBLIC" {
		return fail(protocol.FailureTargetRejected, "scope environment is invalid")
	}
	if job.RiskClass != protocol.RiskPassive && job.RiskClass != protocol.RiskSafeActive && job.RiskClass != protocol.RiskControlledActive {
		return fail(protocol.FailureInvalidJob, "risk class is invalid")
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if job.IssuedAt.IsZero() || job.IssuedAt.After(now.Add(5*time.Minute)) || job.ExpiresAt.IsZero() || !job.ExpiresAt.After(now) || !job.ExpiresAt.After(job.IssuedAt) {
		return fail(protocol.FailureJobExpired, "job issue or expiry time is invalid")
	}
	if job.TimeoutSeconds < 1 || job.TimeoutSeconds > 14400 {
		return fail(protocol.FailureInvalidJob, "job timeout is outside protocol bounds")
	}
	if err := ValidateTarget(job.Target); err != nil {
		return fail(protocol.FailureTargetRejected, err.Error())
	}
	if job.Signature != "" || job.SignatureAlgorithm != "" {
		return fail(protocol.FailureSignature, "signed job envelopes are not active in Control Plane protocol v1")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = make(map[string]time.Time)
	}
	for nonce, expiry := range v.seen {
		if !expiry.After(now) {
			delete(v.seen, nonce)
		}
	}
	if _, exists := v.seen[job.Nonce]; exists {
		return fail(protocol.FailureInvalidJob, "job nonce was already accepted")
	}
	if len(v.seen) >= 4096 {
		return fail(protocol.FailureInternal, "job nonce cache reached its safety limit")
	}
	v.seen[job.Nonce] = job.ExpiresAt
	return nil
}

func ValidateModuleVersion(required, available string) error {
	if required != available {
		return &VerificationError{Code: protocol.FailureModuleUnavailable, Err: fmt.Errorf("module version %s is required; agent provides %s", required, available)}
	}
	return nil
}
