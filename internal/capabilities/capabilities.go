package capabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Capability struct {
	ID          string `json:"id"`
	Available   bool   `json:"available"`
	Tool        string `json:"tool,omitempty"`
	ToolVersion string `json:"toolVersion,omitempty"`
	Reason      string `json:"reason,omitempty"`
}
type Report struct {
	OS           string       `json:"os"`
	Architecture string       `json:"architecture"`
	Items        []Capability `json:"items"`
}

func Discover(ctx context.Context) Report {
	items := []Capability{{ID: "DNS", Available: true}, {ID: "TCP", Available: true}, {ID: "HTTP", Available: true}, {ID: "TLS", Available: true}}
	if runtime.GOOS == "windows" {
		items = append(items, binary(ctx, "PING", "ping", []string{"/?"}), binary(ctx, "TRACEROUTE", "tracert", []string{"/?"}))
	} else {
		items = append(items, binary(ctx, "PING", "ping", []string{"-V"}), binary(ctx, "TRACEROUTE", "traceroute", []string{"--version"}))
	}
	for _, t := range []struct {
		id, name string
		args     []string
	}{{"NMAP", "nmap", []string{"--version"}}, {"TSHARK", "tshark", []string{"--version"}}, {"ZEEK", "zeek", []string{"--version"}}, {"SURICATA", "suricata", []string{"--build-info"}}, {"IPERF3", "iperf3", []string{"--version"}}} {
		items = append(items, binary(ctx, t.id, t.name, t.args))
	}
	return Report{OS: runtime.GOOS, Architecture: runtime.GOARCH, Items: items}
}

func binary(parent context.Context, id, name string, args []string) Capability {
	p, err := exec.LookPath(name)
	if err != nil {
		return Capability{ID: id, Available: false, Tool: name, Reason: "tool not found"}
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = []string{"PATH=" + minimalPath()}
	out, err := cmd.CombinedOutput()
	if len(out) > 256 {
		out = out[:256]
	}
	version := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	if ctx.Err() != nil {
		return Capability{ID: id, Available: true, Tool: name, Reason: "version detection timed out"}
	}
	if err != nil && version == "" {
		return Capability{ID: id, Available: true, Tool: name, Reason: "version unavailable"}
	}
	return Capability{ID: id, Available: true, Tool: name, ToolVersion: version}
}
func minimalPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32;C:\Windows`
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}
func (r Report) Hash() string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (r Report) Has(id string) bool {
	for _, c := range r.Items {
		if c.ID == id {
			return c.Available
		}
	}
	return false
}
