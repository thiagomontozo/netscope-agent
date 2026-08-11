package heartbeat

import (
	"context"
	"github.com/thiagomontozo/netscope-agent/internal/capabilities"
	"os"
	"runtime"
	"time"
)

type Source interface{ Running() int }
type SpoolHealth interface{ Health() (int, int64, error) }
type Payload struct {
	AgentID          string    `json:"agentId"`
	Version          string    `json:"version"`
	ProtocolVersion  string    `json:"protocolVersion"`
	Hostname         string    `json:"hostname"`
	OS               string    `json:"os"`
	Architecture     string    `json:"architecture"`
	Goroutines       int       `json:"currentLoadGoroutines"`
	RunningJobs      int       `json:"runningJobs"`
	AvailableSlots   int       `json:"availableSlots"`
	CapabilitiesHash string    `json:"capabilitiesHash"`
	Timestamp        time.Time `json:"timestamp"`
	Zone             string    `json:"zone"`
	SpoolItems       int       `json:"spoolItems"`
	SpoolBytes       int64     `json:"spoolBytes"`
	Healthy          bool      `json:"healthy"`
}

func Build(_ context.Context, agentID, version, protocol, zone string, max int, c capabilities.Report, run Source, spool SpoolHealth) Payload {
	host, _ := os.Hostname()
	items, b, err := spool.Health()
	running := run.Running()
	return Payload{AgentID: agentID, Version: version, ProtocolVersion: protocol, Hostname: host, OS: runtime.GOOS, Architecture: runtime.GOARCH, Goroutines: runtime.NumGoroutine(), RunningJobs: running, AvailableSlots: max - running, CapabilitiesHash: c.Hash(), Timestamp: time.Now().UTC(), Zone: zone, SpoolItems: items, SpoolBytes: b, Healthy: err == nil}
}
