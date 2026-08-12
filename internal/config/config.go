package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/identity"
)

const (
	DefaultMaxStdoutBytes int64 = 1 << 20
	DefaultMaxStderrBytes int64 = 256 << 10
	DefaultMaxResultBytes int64 = 2 << 20
	DefaultMaxSpoolBytes  int64 = 32 << 20
)

type Config struct {
	ControlPlaneURL   string
	AgentName         string
	EnrollmentToken   string
	DataDir           string
	LogLevel          string
	HeartbeatInterval time.Duration
	JobPollInterval   time.Duration
	MaxConcurrentJobs int
	MaxJobTimeout     time.Duration
	RequestTimeout    time.Duration
	MaxStdoutBytes    int64
	MaxStderrBytes    int64
	MaxResultBytes    int64
	MaxSpoolBytes     int64
	MaxSpoolAge       time.Duration
	ServerCAPath      string
	NetworkZone       string
	RequireSignedJobs bool
}

func Load() (Config, error) {
	c := Config{
		ControlPlaneURL:   strings.TrimSpace(os.Getenv("NETSCOPE_CONTROL_PLANE_URL")),
		AgentName:         env("NETSCOPE_AGENT_NAME", "netscope-agent"),
		EnrollmentToken:   os.Getenv("NETSCOPE_ENROLLMENT_TOKEN"),
		DataDir:           env("NETSCOPE_DATA_DIR", "./data"),
		LogLevel:          env("NETSCOPE_LOG_LEVEL", "info"),
		HeartbeatInterval: duration("NETSCOPE_HEARTBEAT_INTERVAL", 30*time.Second),
		JobPollInterval:   duration("NETSCOPE_JOB_POLL_INTERVAL", 5*time.Second),
		MaxConcurrentJobs: integer("NETSCOPE_MAX_CONCURRENT_JOBS", 2),
		MaxJobTimeout:     duration("NETSCOPE_MAX_JOB_TIMEOUT", 10*time.Minute),
		RequestTimeout:    duration("NETSCOPE_REQUEST_TIMEOUT", 30*time.Second),
		MaxStdoutBytes:    bytes("NETSCOPE_MAX_STDOUT_BYTES", DefaultMaxStdoutBytes),
		MaxStderrBytes:    bytes("NETSCOPE_MAX_STDERR_BYTES", DefaultMaxStderrBytes),
		MaxResultBytes:    bytes("NETSCOPE_MAX_RESULT_BYTES", DefaultMaxResultBytes),
		MaxSpoolBytes:     bytes("NETSCOPE_MAX_SPOOL_BYTES", DefaultMaxSpoolBytes),
		MaxSpoolAge:       duration("NETSCOPE_MAX_SPOOL_AGE", 24*time.Hour),
		ServerCAPath:      firstNonEmpty(os.Getenv("NETSCOPE_SERVER_CA_CERT"), os.Getenv("NETSCOPE_CA_CERT")),
		NetworkZone:       env("NETSCOPE_NETWORK_ZONE", "INTERNAL"),
		RequireSignedJobs: boolean("NETSCOPE_REQUIRE_SIGNED_JOBS", true),
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	for _, dir := range []string{"spool", "temp", "state"} {
		if err := os.MkdirAll(filepath.Join(c.DataDir, dir), 0o700); err != nil {
			return Config{}, fmt.Errorf("create data directory: %w", err)
		}
	}
	return c, nil
}

func (c Config) Validate() error {
	if (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return errors.New("this Agent build does not implement the Control Plane platform contract")
	}
	u, err := url.Parse(c.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("NETSCOPE_CONTROL_PLANE_URL must be an absolute HTTPS URL without credentials")
	}
	if c.AgentName == "" || c.MaxConcurrentJobs < 1 || c.MaxConcurrentJobs > 32 || c.MaxJobTimeout <= 0 || c.JobPollInterval <= 0 {
		return errors.New("invalid agent name, concurrency, timeout, or poll interval")
	}
	if c.HeartbeatInterval < 10*time.Second || c.HeartbeatInterval > 60*time.Second {
		return errors.New("NETSCOPE_HEARTBEAT_INTERVAL must be between 10s and 60s")
	}
	if c.MaxResultBytes > 2<<20 {
		return errors.New("NETSCOPE_MAX_RESULT_BYTES cannot exceed the Control Plane 2 MiB request limit")
	}
	return nil
}

func (c Config) TLSConfig(id *identity.Identity) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.ServerCAPath != "" {
		certificatePEM, err := os.ReadFile(c.ServerCAPath)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(certificatePEM) {
			return nil, errors.New("server CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	if id != nil {
		certificate, err := id.TLSCertificate()
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func duration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(key))
	if err == nil && value > 0 {
		return value
	}
	return fallback
}

func integer(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err == nil && value > 0 {
		return value
	}
	return fallback
}

func bytes(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err == nil && value > 0 {
		return value
	}
	return fallback
}

func boolean(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
