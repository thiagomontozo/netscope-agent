package enrollment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/thiagomontozo/netscope-agent/internal/client"
	"github.com/thiagomontozo/netscope-agent/internal/identity"
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

func Ensure(ctx context.Context, dataDir, name, token, version, networkZone string, capabilitySummary []string, api *client.Client) (*identity.Identity, bool, error) {
	id, err := identity.Load(dataDir)
	if err != nil {
		return nil, false, err
	}
	if id != nil {
		return id, false, nil
	}
	if len(strings.TrimSpace(token)) < 32 {
		return nil, false, errors.New("first enrollment requires a valid NETSCOPE_ENROLLMENT_TOKEN")
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return nil, false, errors.New("hostname is required for enrollment")
	}
	pending, err := identity.Generate(name, hostname)
	if err != nil {
		return nil, false, err
	}
	sort.Strings(capabilitySummary)
	request := protocol.EnrollmentRequest{ProtocolVersion: protocol.Version, EnrollmentToken: token, AgentName: name, Hostname: hostname, OS: runtime.GOOS, Architecture: runtime.GOARCH, AgentVersion: version, PublicIdentity: protocol.PublicIdentity{CSRPEM: pending.CSRPEM}, CapabilitiesSummary: capabilitySummary, NetworkZone: networkZone}
	response, err := api.Enroll(ctx, request)
	if err != nil {
		return nil, false, fmt.Errorf("enrollment failed: %w", err)
	}
	id, err = identity.SaveEnrollment(dataDir, pending, response)
	if err != nil {
		return nil, false, err
	}
	_ = os.Unsetenv("NETSCOPE_ENROLLMENT_TOKEN")
	return id, true, nil
}
