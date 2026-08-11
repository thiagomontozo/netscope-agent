package capabilities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/modules"
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

type Report struct {
	Manifest  protocol.CapabilityManifest
	available map[string]bool
}

type toolState struct {
	Name      string
	Version   string
	Available bool
}

func Discover(ctx context.Context, agentID string, registry *modules.Registry) Report {
	toolNames := []string{"ping", routeTool(), "nmap", "tshark", "zeek", "suricata", "iperf3", "greenbone"}
	tools := make(map[string]toolState, len(toolNames))
	external := make([]protocol.ExternalTool, 0, len(toolNames))
	for _, name := range toolNames {
		state := detectTool(ctx, name)
		tools[name] = state
		external = append(external, protocol.ExternalTool{Name: state.Name, Version: state.Version, Available: state.Available})
	}
	sort.Slice(external, func(i, j int) bool { return external[i].Name < external[j].Name })

	manifest := protocol.CapabilityManifest{ProtocolVersion: protocol.Version, AgentID: agentID, Platform: runtime.GOOS + "/" + runtime.GOARCH, ExternalTools: external, ArtifactCapabilities: []string{}}
	available := make(map[string]bool)
	for _, descriptor := range registry.Descriptors() {
		isAvailable := supportedPlatform(descriptor.Platforms, runtime.GOOS)
		if descriptor.RequiredTool != "" {
			isAvailable = isAvailable && tools[descriptor.RequiredTool].Available
		}
		// Protocol v1 has artifact metadata registration but no authorized
		// artifact content delivery contract. These adapters remain compiled but
		// are deliberately not advertised until that contract exists.
		if strings.HasPrefix(descriptor.ID, "traffic.") || descriptor.ID == "security.suricata" || descriptor.ID == "performance.iperf3" {
			isAvailable = false
		}
		manifest.Modules = append(manifest.Modules, protocol.ModuleCapability{ModuleID: descriptor.ID, CapabilityID: descriptor.RequiredCapability, Available: isAvailable, Implementation: descriptor.Implementation, ModuleVersion: descriptor.Version, RiskClasses: []protocol.RiskClass{descriptor.RiskClass}})
		available[descriptor.RequiredCapability] = isAvailable
		if isAvailable {
			manifest.NetworkCapabilities = append(manifest.NetworkCapabilities, descriptor.RequiredCapability)
		}
	}
	sort.Slice(manifest.Modules, func(i, j int) bool { return manifest.Modules[i].ModuleID < manifest.Modules[j].ModuleID })
	sort.Strings(manifest.NetworkCapabilities)
	return Report{Manifest: manifest, available: available}
}

func detectTool(parent context.Context, name string) toolState {
	state := toolState{Name: name}
	path, err := exec.LookPath(name)
	if err != nil {
		return state
	}
	state.Available = true
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	args := versionArguments(name)
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=" + minimalPath()}
	output, err := command.CombinedOutput()
	if len(output) > 256 {
		output = output[:256]
	}
	if err == nil || len(output) > 0 {
		state.Version = strings.TrimSpace(strings.Split(string(output), "\n")[0])
	}
	return state
}

func versionArguments(name string) []string {
	if runtime.GOOS == "windows" && (name == "ping" || name == "tracert") {
		return []string{"/?"}
	}
	if name == "suricata" {
		return []string{"--build-info"}
	}
	return []string{"--version"}
}

func routeTool() string {
	if runtime.GOOS == "windows" {
		return "tracert"
	}
	return "traceroute"
}

func minimalPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32;C:\Windows`
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

func supportedPlatform(platforms []string, current string) bool {
	for _, platform := range platforms {
		if platform == current {
			return true
		}
	}
	return false
}

func (r Report) Hash() string {
	encoded, _ := json.Marshal(r.Manifest)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (r Report) Has(capabilityID string) bool { return r.available[capabilityID] }

func (r Report) Summary() []string {
	items := make([]string, 0, len(r.available))
	for capabilityID, available := range r.available {
		if available {
			items = append(items, capabilityID)
		}
	}
	sort.Strings(items)
	return items
}
