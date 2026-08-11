package jobs

import (
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

const ProtocolVersion = protocol.Version

type RiskClass = protocol.RiskClass

const (
	RiskPassive          = protocol.RiskPassive
	RiskSafeActive       = protocol.RiskSafeActive
	RiskControlledActive = protocol.RiskControlledActive
)

type Envelope = protocol.JobEnvelope

// Observation and ModuleResult are internal execution records. The Executor is
// the only component that normalizes them into protocol.JobResult.
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
	Warnings     []string           `json:"warnings,omitempty"`
	Truncated    bool               `json:"truncated"`
	ToolVersion  string             `json:"toolVersion,omitempty"`
}
