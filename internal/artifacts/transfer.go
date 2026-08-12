package artifacts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var ErrChecksumMismatch = errors.New("ARTIFACT_CHECKSUM_MISMATCH")
var ErrSizeLimit = errors.New("ARTIFACT_SIZE_LIMIT_EXCEEDED")

type Transfer struct {
	HTTP             *http.Client
	MaxDownloadBytes int64
	MaxUploadBytes   int64
	TempDir          string
}

func (t Transfer) Download(ctx context.Context, transferURL, token, artifactID string, expectedSize int64, expectedSHA256 string) (string, error) {
	if err := safeTransferURL(transferURL); err != nil {
		return "", err
	}
	if expectedSize < 0 || expectedSize > t.MaxDownloadBytes {
		return "", ErrSizeLimit
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, transferURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Artifact "+token)
	response, err := t.HTTP.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifact download failed with status %d", response.StatusCode)
	}
	file, err := os.CreateTemp(t.TempDir, ".artifact-"+safeID(artifactID)+"-*.part")
	if err != nil {
		return "", err
	}
	path := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := copyVerified(file, response.Body, expectedSize, t.MaxDownloadBytes, expectedSHA256); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	committed = true
	return path, nil
}

func (t Transfer) Upload(ctx context.Context, transferURL, token, path, expectedSHA256 string) error {
	if err := safeTransferURL(transferURL); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > t.MaxUploadBytes {
		return ErrSizeLimit
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, transferURL, io.LimitReader(io.TeeReader(file, hash), t.MaxUploadBytes+1))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Artifact "+token)
	request.ContentLength = info.Size()
	request.Header.Set("X-NetScope-Artifact-SHA256", strings.ToLower(expectedSHA256))
	response, err := t.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("artifact upload failed with status %d", response.StatusCode)
	}
	if !hmac.Equal([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(strings.ToLower(expectedSHA256))) {
		return ErrChecksumMismatch
	}
	return nil
}

func safeTransferURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return errors.New("artifact transfer URL is invalid")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return errors.New("artifact transfer URL must use HTTPS")
}

func copyVerified(destination io.Writer, source io.Reader, expectedSize, maximum int64, expectedSHA256 string) (int64, error) {
	if maximum < 1 || expectedSize > maximum {
		return 0, ErrSizeLimit
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: source, N: maximum + 1}
	written, err := io.Copy(io.MultiWriter(destination, hash), limited)
	if err != nil {
		return written, err
	}
	if written > maximum {
		return written, ErrSizeLimit
	}
	if written != expectedSize {
		return written, errors.New("artifact final size differs from manifest")
	}
	if !hmac.Equal([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(strings.ToLower(expectedSHA256))) {
		return written, ErrChecksumMismatch
	}
	return written, nil
}

func safeID(id string) string {
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return "opaque"
		}
	}
	return filepath.Base(id)
}
