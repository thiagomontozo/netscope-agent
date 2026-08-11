package jobs

import (
	"encoding/json"
	"time"
)

const ProtocolVersion = "1.0"

type RiskClass string

const (
	RiskPassive          RiskClass = "PASSIVE"
	RiskSafeActive       RiskClass = "SAFE_ACTIVE"
	RiskControlledActive RiskClass = "CONTROLLED_ACTIVE"
)

type Target struct {
	Host               string    `json:"host,omitempty"`
	Port               int       `json:"port,omitempty"`
	URL                string    `json:"url,omitempty"`
	ArtifactReference  string    `json:"artifactReference,omitempty"`
	ArtifactSHA256     string    `json:"artifactSha256,omitempty"`
	ArtifactSize       int64     `json:"artifactSize,omitempty"`
	ArtifactExpiresAt  time.Time `json:"artifactExpiresAt,omitempty"`
	ControlledEndpoint bool      `json:"controlledEndpoint,omitempty"`
}
type Scope struct {
	Environment            string `json:"scopeEnvironment"`
	ID                     string `json:"scopeId"`
	AuthorizationReference string `json:"authorizationReference"`
}
type Envelope struct {
	ProtocolVersion string          `json:"protocolVersion"`
	JobID           string          `json:"jobId"`
	AgentID         string          `json:"agentId"`
	OrganizationID  string          `json:"organizationId"`
	ModuleID        string          `json:"moduleId"`
	ModuleVersion   string          `json:"moduleVersion,omitempty"`
	Scope           Scope           `json:"scope"`
	Target          Target          `json:"target"`
	Parameters      json.RawMessage `json:"parameters"`
	RiskClass       RiskClass       `json:"riskClass"`
	IssuedAt        time.Time       `json:"issuedAt"`
	ExpiresAt       time.Time       `json:"expiresAt"`
	Nonce           string          `json:"nonce"`
	Signature       string          `json:"signature,omitempty"`
}

type Evidence struct {
	Name              string `json:"name"`
	MediaType         string `json:"mediaType"`
	Size              int64  `json:"size"`
	SHA256            string `json:"sha256"`
	ArtifactReference string `json:"artifactReference,omitempty"`
}
type Observation struct {
	Kind    string         `json:"kind"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}
type ModuleResult struct {
	JobID        string             `json:"jobId"`
	ModuleID     string             `json:"moduleId"`
	Status       string             `json:"status"`
	StartedAt    time.Time          `json:"startedAt"`
	CompletedAt  time.Time          `json:"completedAt"`
	Summary      string             `json:"summary"`
	Observations []Observation      `json:"observations,omitempty"`
	Metrics      map[string]float64 `json:"metrics,omitempty"`
	Evidence     []Evidence         `json:"evidence,omitempty"`
	Warnings     []string           `json:"warnings,omitempty"`
	Truncated    bool               `json:"truncated"`
	ToolVersion  string             `json:"toolVersion,omitempty"`
	ErrorCode    string             `json:"errorCode,omitempty"`
}

const (
	ErrModuleUnavailable       = "MODULE_UNAVAILABLE"
	ErrToolNotFound            = "TOOL_NOT_FOUND"
	ErrCapabilityMissing       = "CAPABILITY_MISSING"
	ErrInvalidJob              = "INVALID_JOB"
	ErrJobExpired              = "JOB_EXPIRED"
	ErrTargetRejected          = "TARGET_REJECTED"
	ErrTimeout                 = "TIMEOUT"
	ErrProcessFailed           = "PROCESS_FAILED"
	ErrOutputLimitExceeded     = "OUTPUT_LIMIT_EXCEEDED"
	ErrArtifact                = "ARTIFACT_ERROR"
	ErrControlPlaneUnavailable = "CONTROL_PLANE_UNAVAILABLE"
)
