package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/jobs"
)

type Manager struct {
	DataDir          string
	MaxArtifactBytes int64
	HTTP             *http.Client
}

func (m Manager) Download(ctx context.Context, t jobs.Target) (string, func(), error) {
	if t.ArtifactReference == "" || t.ArtifactSHA256 == "" || t.ArtifactSize < 1 || t.ArtifactSize > m.MaxArtifactBytes {
		return "", nil, errors.New("artifact metadata incomplete or outside size limit")
	}
	if t.ArtifactExpiresAt.IsZero() || !t.ArtifactExpiresAt.After(time.Now().UTC()) {
		return "", nil, errors.New("artifact reference expired")
	}
	u, err := url.Parse(t.ArtifactReference)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", nil, errors.New("artifact reference must be HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("artifact server returned HTTP %d", resp.StatusCode)
	}
	f, err := os.CreateTemp(filepath.Join(m.DataDir, "temp"), "pcap-*.artifact")
	if err != nil {
		return "", nil, err
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, m.MaxArtifactBytes+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n > m.MaxArtifactBytes || n != t.ArtifactSize {
		cleanup()
		return "", nil, errors.New("artifact size validation failed")
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), t.ArtifactSHA256) {
		cleanup()
		return "", nil, errors.New("artifact checksum validation failed")
	}
	return name, cleanup, nil
}
