package suricata

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/thiagomontozo/netscope-agent/internal/jobs"
	"github.com/thiagomontozo/netscope-agent/internal/modules"
	nprocess "github.com/thiagomontozo/netscope-agent/internal/process"
	"github.com/thiagomontozo/netscope-agent/internal/security"
	"os"
	"path/filepath"
	"time"
)

type Module struct {
	Runner  nprocess.Runner
	DataDir string
}

func New(r nprocess.Runner, d string) Module { return Module{r, d} }
func (Module) Descriptor() modules.Descriptor {
	return modules.Descriptor{ID: "security.suricata", Version: "1.0.0", RiskClass: jobs.RiskPassive, RequiredTool: "suricata", RequiredCapability: "SURICATA", Platforms: []string{"linux", "windows", "darwin"}, ConcurrencyLimit: 1}
}
func (m Module) Validate(j jobs.Envelope) error {
	if len(j.Parameters) > 0 && string(j.Parameters) != "{}" && string(j.Parameters) != "null" {
		return errors.New("Suricata v0.1 accepts no parameters")
	}
	return security.ValidateTemporaryArtifact(m.DataDir, j.Target.ArtifactReference)
}
func (m Module) Execute(ctx context.Context, j jobs.Envelope) (jobs.ModuleResult, error) {
	start := time.Now().UTC()
	dir, err := os.MkdirTemp(filepath.Join(m.DataDir, "temp"), "suricata-*")
	if err != nil {
		return jobs.ModuleResult{}, err
	}
	defer os.RemoveAll(dir)
	out, err := m.Runner.Run(ctx, "suricata", "-r", j.Target.ArtifactReference, "-l", dir)
	alerts := 0
	if f, e := os.Open(filepath.Join(dir, "eve.json")); e == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 64<<10), 1<<20)
		for s.Scan() {
			var v struct {
				EventType string `json:"event_type"`
			}
			if json.Unmarshal(s.Bytes(), &v) == nil && v.EventType == "alert" {
				alerts++
			}
		}
	}
	return jobs.ModuleResult{JobID: j.JobID, ModuleID: j.ModuleID, StartedAt: start, CompletedAt: time.Now().UTC(), Status: "COMPLETED", Summary: "Suricata offline PCAP analysis completed", Metrics: map[string]float64{"alertCount": float64(alerts)}, Truncated: out.StdoutTruncated || out.StderrTruncated}, err
}
