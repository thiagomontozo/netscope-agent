package security

import (
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

var hostname = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$`)

func ValidateHost(value string) error {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "/\\\x00\r\n \t") {
		return errors.New("invalid host")
	}
	trimmed := strings.Trim(value, "[]")
	if net.ParseIP(trimmed) != nil {
		return nil
	}
	if !hostname.MatchString(value) {
		return errors.New("invalid hostname")
	}
	return nil
}

func ValidateTemporaryArtifact(dataDir, artifactPath string) error {
	if artifactPath == "" {
		return errors.New("artifact path required")
	}
	root, err := filepath.Abs(filepath.Join(dataDir, "temp"))
	if err != nil {
		return err
	}
	p, err := filepath.Abs(artifactPath)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("artifact path escapes controlled temporary directory")
	}
	return nil
}
