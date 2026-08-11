package enrollment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/thiagomontozo/netscope-agent/internal/client"
	"github.com/thiagomontozo/netscope-agent/internal/identity"
)

func Ensure(ctx context.Context, dataDir, name, token, version string, api *client.Client) (*identity.Identity, error) {
	id, err := identity.Load(dataDir)
	if err != nil {
		return nil, err
	}
	if id != nil {
		return id, nil
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("first enrollment requires NETSCOPE_ENROLLMENT_TOKEN")
	}
	id, err = identity.Generate()
	if err != nil {
		return nil, err
	}
	resp, err := api.Enroll(ctx, token, client.EnrollRequest{Name: name, PublicKey: id.PublicKey, OS: runtime.GOOS, Architecture: runtime.GOARCH, Version: version})
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}
	if resp.AgentID == "" || resp.Credential == "" {
		return nil, errors.New("enrollment response omitted permanent identity fields")
	}
	id.AgentID = resp.AgentID
	id.Credential = resp.Credential
	if err := identity.Save(dataDir, id); err != nil {
		return nil, err
	}
	if resp.ControlPlaneSigningKey != "" {
		p := filepath.Join(dataDir, "identity", "control-plane-signing-key")
		if err := os.WriteFile(p, []byte(resp.ControlPlaneSigningKey+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return id, nil
}
