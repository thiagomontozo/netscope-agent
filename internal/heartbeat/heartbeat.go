package heartbeat

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/capabilities"
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

type Source interface {
	Running() int
	LastResult() *protocol.LastJobResult
}

type SpoolHealth interface{ Health() (int, int64, error) }

func Build(_ context.Context, agentID, agentVersion string, maximum int, capabilityReport capabilities.Report, running Source, spool SpoolHealth) protocol.Heartbeat {
	hostname, _ := os.Hostname()
	items, spoolBytes, spoolErr := spool.Health()
	active := running.Running()
	available := maximum - active
	if available < 0 {
		available = 0
	}
	status := "ONLINE"
	spoolStatus := "HEALTHY"
	if spoolErr != nil {
		status = "DEGRADED"
		spoolStatus = "UNAVAILABLE"
	}
	return protocol.Heartbeat{
		ProtocolVersion:         protocol.Version,
		AgentID:                 agentID,
		AgentVersion:            agentVersion,
		ContractVersion:         protocol.ContractVersion,
		CapabilitySchemaVersion: protocol.CapabilitySchemaVersion,
		Timestamp:               time.Now().UTC(),
		Hostname:                hostname,
		OS:                      runtime.GOOS,
		Architecture:            runtime.GOARCH,
		Status:                  status,
		RunningJobs:             active,
		AvailableSlots:          available,
		CapabilitiesHash:        capabilityReport.Hash(),
		HealthSummary:           map[string]any{"identity": "VALID", "spool": spoolStatus, "spoolItems": items, "spoolBytes": spoolBytes, "capabilityManifest": "LOADED"},
		LastJobResult:           running.LastResult(),
	}
}
