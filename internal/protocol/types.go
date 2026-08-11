package protocol

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const Version = "1.0"

type RiskClass string

const (
	RiskPassive          RiskClass = "PASSIVE"
	RiskSafeActive       RiskClass = "SAFE_ACTIVE"
	RiskControlledActive RiskClass = "CONTROLLED_ACTIVE"
)

type Status string

const (
	StatusHealthy       Status = "HEALTHY"
	StatusInformational Status = "INFORMATIONAL"
	StatusAttention     Status = "ATTENTION"
	StatusWarning       Status = "WARNING"
	StatusCritical      Status = "CRITICAL"
	StatusInconclusive  Status = "INCONCLUSIVE"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

type EnrollmentRequest struct {
	ProtocolVersion     string            `json:"protocolVersion"`
	EnrollmentToken     string            `json:"enrollmentToken"`
	AgentName           string            `json:"agentName"`
	Hostname            string            `json:"hostname"`
	OS                  string            `json:"os"`
	Architecture        string            `json:"architecture"`
	AgentVersion        string            `json:"agentVersion"`
	PublicIdentity      PublicIdentity    `json:"publicIdentity"`
	CapabilitiesSummary []string          `json:"capabilitiesSummary"`
	Labels              map[string]string `json:"labels,omitempty"`
	NetworkZone         string            `json:"networkZone,omitempty"`
}

type PublicIdentity struct {
	CSRPEM string `json:"csrPem"`
}

type EnrollmentResponse struct {
	ProtocolVersion      string               `json:"protocolVersion"`
	AgentID              string               `json:"agentId"`
	OrganizationID       string               `json:"organizationId"`
	Status               string               `json:"status"`
	ControlPlaneIdentity ControlPlaneIdentity `json:"controlPlaneIdentity"`
	AgentCredential      AgentCredential      `json:"agentCredential"`
	ServerTime           time.Time            `json:"serverTime"`
}

type ControlPlaneIdentity struct {
	CACertificatePEM    string `json:"caCertificatePem"`
	JobSigningPublicKey string `json:"jobSigningPublicKey,omitempty"`
}

type AgentCredential struct {
	CertificatePEM string    `json:"certificatePem"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type Heartbeat struct {
	ProtocolVersion  string         `json:"protocolVersion"`
	AgentID          string         `json:"agentId"`
	AgentVersion     string         `json:"agentVersion"`
	Timestamp        time.Time      `json:"timestamp"`
	Hostname         string         `json:"hostname"`
	OS               string         `json:"os"`
	Architecture     string         `json:"architecture"`
	Status           string         `json:"status"`
	RunningJobs      int            `json:"runningJobs"`
	AvailableSlots   int            `json:"availableSlots"`
	CapabilitiesHash string         `json:"capabilitiesHash"`
	HealthSummary    map[string]any `json:"healthSummary"`
	LastJobResult    *LastJobResult `json:"lastJobResult,omitempty"`
}

type LastJobResult struct {
	JobID       string    `json:"jobId"`
	Status      string    `json:"status"`
	CompletedAt time.Time `json:"completedAt"`
}

type HeartbeatResponse struct {
	Status              string    `json:"status"`
	ProtocolVersion     string    `json:"protocolVersion"`
	CompatibilityStatus string    `json:"compatibilityStatus"`
	ServerTime          time.Time `json:"serverTime"`
}

type CapabilityManifest struct {
	ProtocolVersion      string             `json:"protocolVersion"`
	AgentID              string             `json:"agentId"`
	Platform             string             `json:"platform"`
	Modules              []ModuleCapability `json:"modules"`
	ExternalTools        []ExternalTool     `json:"externalTools"`
	NetworkCapabilities  []string           `json:"networkCapabilities"`
	ArtifactCapabilities []string           `json:"artifactCapabilities"`
}

type ModuleCapability struct {
	ModuleID       string      `json:"moduleId"`
	CapabilityID   string      `json:"capabilityId"`
	Available      bool        `json:"available"`
	Implementation string      `json:"implementation"`
	ModuleVersion  string      `json:"moduleVersion"`
	RiskClasses    []RiskClass `json:"riskClasses"`
}

type ExternalTool struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Available bool   `json:"available"`
}

type CapabilityResponse struct {
	CapabilitiesHash string `json:"capabilitiesHash"`
}

type JobTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type JobEnvelope struct {
	ProtocolVersion          string          `json:"protocolVersion"`
	JobID                    string          `json:"jobId"`
	OrganizationID           string          `json:"organizationId"`
	AgentID                  string          `json:"agentId"`
	ModuleID                 string          `json:"moduleId"`
	ModuleVersionRequirement string          `json:"moduleVersionRequirement"`
	ScopeID                  string          `json:"scopeId"`
	ScopeEnvironment         string          `json:"scopeEnvironment"`
	AssetID                  *string         `json:"assetId,omitempty"`
	ServiceID                *string         `json:"serviceId,omitempty"`
	DiagnosticRunID          *string         `json:"diagnosticRunId,omitempty"`
	VantagePointID           *string         `json:"vantagePointId,omitempty"`
	Target                   JobTarget       `json:"target"`
	ValidatedParameters      json.RawMessage `json:"validatedParameters"`
	RiskClass                RiskClass       `json:"riskClass"`
	AuthorizationReference   string          `json:"authorizationReference"`
	IssuedAt                 time.Time       `json:"issuedAt"`
	ExpiresAt                time.Time       `json:"expiresAt"`
	TimeoutSeconds           int             `json:"timeoutSeconds"`
	Nonce                    string          `json:"nonce"`
	SignatureAlgorithm       string          `json:"signatureAlgorithm,omitempty"`
	Signature                string          `json:"signature,omitempty"`
}

type Observation struct {
	AssetID         *string    `json:"assetId,omitempty"`
	Category        string     `json:"category"`
	Status          Status     `json:"status"`
	Severity        string     `json:"severity"`
	Confidence      Confidence `json:"confidence"`
	Title           string     `json:"title"`
	Summary         string     `json:"summary"`
	Meaning         string     `json:"meaning"`
	Impact          string     `json:"impact"`
	SuggestedAction string     `json:"suggestedAction"`
	ObservedAt      time.Time  `json:"observedAt"`
}

type Metric struct {
	Name         string    `json:"name"`
	NumericValue *float64  `json:"numericValue,omitempty"`
	TextValue    string    `json:"textValue,omitempty"`
	Status       Status    `json:"status"`
	ObservedAt   time.Time `json:"observedAt"`
}

type EvidenceManifest struct {
	EvidenceID     string          `json:"evidenceId"`
	Source         string          `json:"source"`
	ContentType    string          `json:"contentType"`
	Summary        string          `json:"summary"`
	StructuredData json.RawMessage `json:"structuredData"`
	SHA256         string          `json:"sha256"`
	SizeBytes      int64           `json:"sizeBytes"`
	ArtifactKind   string          `json:"artifactKind"`
}

type JobResult struct {
	ProtocolVersion  string             `json:"protocolVersion"`
	ResultIdentity   string             `json:"resultIdentity"`
	ResultVersion    int                `json:"resultVersion"`
	JobID            string             `json:"jobId"`
	AgentID          string             `json:"agentId"`
	ModuleID         string             `json:"moduleId"`
	Status           string             `json:"status"`
	StartedAt        time.Time          `json:"startedAt"`
	CompletedAt      time.Time          `json:"completedAt"`
	Summary          string             `json:"summary"`
	Observations     []Observation      `json:"observations"`
	Metrics          []Metric           `json:"metrics"`
	Warnings         []string           `json:"warnings"`
	EvidenceManifest []EvidenceManifest `json:"evidenceManifest"`
	ToolVersion      string             `json:"toolVersion,omitempty"`
	Truncated        bool               `json:"truncated"`
}

type FailureCode string

const (
	FailureModuleUnavailable   FailureCode = "MODULE_UNAVAILABLE"
	FailureToolNotFound        FailureCode = "TOOL_NOT_FOUND"
	FailureCapabilityMissing   FailureCode = "CAPABILITY_MISSING"
	FailureInvalidJob          FailureCode = "INVALID_JOB"
	FailureJobExpired          FailureCode = "JOB_EXPIRED"
	FailureTargetRejected      FailureCode = "TARGET_REJECTED"
	FailureTimeout             FailureCode = "TIMEOUT"
	FailureProcessFailed       FailureCode = "PROCESS_FAILED"
	FailureOutputLimitExceeded FailureCode = "OUTPUT_LIMIT_EXCEEDED"
	FailureArtifact            FailureCode = "ARTIFACT_ERROR"
	FailureCancelled           FailureCode = "CANCELLED"
	FailureProtocol            FailureCode = "PROTOCOL_INCOMPATIBLE"
	FailureSignature           FailureCode = "SIGNATURE_INVALID"
	FailureInternal            FailureCode = "INTERNAL_ERROR"
)

type JobFailure struct {
	ProtocolVersion string      `json:"protocolVersion"`
	JobID           string      `json:"jobId"`
	AgentID         string      `json:"agentId"`
	Code            FailureCode `json:"code"`
	Summary         string      `json:"summary"`
	OccurredAt      time.Time   `json:"occurredAt"`
	Retryable       bool        `json:"retryable"`
}

type JobCancellation struct {
	ProtocolVersion       string     `json:"protocolVersion"`
	JobID                 string     `json:"jobId"`
	CancellationRequested bool       `json:"cancellationRequested"`
	RequestedAt           *time.Time `json:"requestedAt"`
	JobStatus             string     `json:"jobStatus"`
}

type EvidenceRequest struct {
	ProtocolVersion string           `json:"protocolVersion"`
	JobID           string           `json:"jobId"`
	AgentID         string           `json:"agentId"`
	Evidence        EvidenceManifest `json:"evidence"`
}

type ErrorEnvelope struct {
	Error ProtocolError `json:"error"`
}

type ProtocolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

type DataEnvelope[T any] struct {
	Data T `json:"data"`
}

func Compatible(local, remote string) bool {
	lMajor, _, lok := versionParts(local)
	rMajor, _, rok := versionParts(remote)
	return lok && rok && lMajor == rMajor
}

func versionParts(value string) (int, int, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	return major, minor, majorErr == nil && minorErr == nil && major >= 0 && minor >= 0
}

func RequireCompatible(remote string) error {
	if !Compatible(Version, remote) {
		return fmt.Errorf("protocol %q is incompatible with agent protocol %s", remote, Version)
	}
	return nil
}
