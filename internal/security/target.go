package security

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
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

func ValidateTarget(target protocol.JobTarget) error {
	if target.Value == "" || len(target.Value) > 2048 || strings.ContainsAny(target.Value, "\x00\r\n") {
		return errors.New("target value is invalid")
	}
	switch target.Type {
	case "HOSTNAME":
		if net.ParseIP(strings.Trim(target.Value, "[]")) != nil {
			return errors.New("HOSTNAME target contains an IP address")
		}
		return ValidateHost(target.Value)
	case "IP":
		if net.ParseIP(strings.Trim(target.Value, "[]")) == nil {
			return errors.New("IP target is invalid")
		}
		return nil
	case "CIDR":
		_, _, err := net.ParseCIDR(target.Value)
		return err
	case "URL":
		u, err := url.Parse(target.Value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("URL target must be an absolute HTTP(S) URL without credentials or fragment")
		}
		return nil
	default:
		return errors.New("target type is unsupported")
	}
}

func Host(target protocol.JobTarget) (string, error) {
	switch target.Type {
	case "HOSTNAME", "IP":
		return strings.Trim(target.Value, "[]"), ValidateTarget(target)
	case "URL":
		if err := ValidateTarget(target); err != nil {
			return "", err
		}
		u, _ := url.Parse(target.Value)
		return u.Hostname(), nil
	default:
		return "", errors.New("module requires a host target")
	}
}
