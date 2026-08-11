package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultMaxStdoutBytes   int64 = 1 << 20
	DefaultMaxStderrBytes   int64 = 256 << 10
	DefaultMaxResultBytes   int64 = 2 << 20
	DefaultMaxArtifactBytes int64 = 64 << 20
	DefaultMaxSpoolBytes    int64 = 32 << 20
)

type Config struct {
	ControlPlaneURL            string
	AgentName                  string
	EnrollmentToken            string
	DataDir                    string
	LogLevel                   string
	JobPollInterval            time.Duration
	MaxConcurrentJobs          int
	DefaultTimeout             time.Duration
	RequestTimeout             time.Duration
	MaxStdoutBytes             int64
	MaxStderrBytes             int64
	MaxResultBytes             int64
	MaxArtifactBytes           int64
	MaxSpoolBytes              int64
	MaxSpoolAge                time.Duration
	CACertPath                 string
	ClientCertPath             string
	ClientKeyPath              string
	ControlPlaneSigningKeyPath string
	Zone                       string
	DevelopmentInsecureTLS     bool
}

func Load() (Config, error) {
	c := Config{
		ControlPlaneURL:   strings.TrimSpace(os.Getenv("NETSCOPE_CONTROL_PLANE_URL")),
		AgentName:         env("NETSCOPE_AGENT_NAME", "netscope-agent"),
		EnrollmentToken:   os.Getenv("NETSCOPE_ENROLLMENT_TOKEN"),
		DataDir:           env("NETSCOPE_DATA_DIR", "./data"),
		LogLevel:          env("NETSCOPE_LOG_LEVEL", "info"),
		JobPollInterval:   duration("NETSCOPE_JOB_POLL_INTERVAL", 5*time.Second),
		MaxConcurrentJobs: integer("NETSCOPE_MAX_CONCURRENT_JOBS", 2),
		DefaultTimeout:    duration("NETSCOPE_DEFAULT_TIMEOUT", 60*time.Second),
		RequestTimeout:    duration("NETSCOPE_REQUEST_TIMEOUT", 30*time.Second),
		MaxStdoutBytes:    bytes("NETSCOPE_MAX_STDOUT_BYTES", DefaultMaxStdoutBytes),
		MaxStderrBytes:    bytes("NETSCOPE_MAX_STDERR_BYTES", DefaultMaxStderrBytes),
		MaxResultBytes:    bytes("NETSCOPE_MAX_RESULT_BYTES", DefaultMaxResultBytes),
		MaxArtifactBytes:  bytes("NETSCOPE_MAX_ARTIFACT_BYTES", DefaultMaxArtifactBytes),
		MaxSpoolBytes:     bytes("NETSCOPE_MAX_SPOOL_BYTES", DefaultMaxSpoolBytes),
		MaxSpoolAge:       duration("NETSCOPE_MAX_SPOOL_AGE", 24*time.Hour),
		CACertPath:        os.Getenv("NETSCOPE_CA_CERT"), ClientCertPath: os.Getenv("NETSCOPE_CLIENT_CERT"),
		ClientKeyPath: os.Getenv("NETSCOPE_CLIENT_KEY"), ControlPlaneSigningKeyPath: os.Getenv("NETSCOPE_CONTROL_PLANE_SIGNING_KEY"),
		Zone:                   env("NETSCOPE_NETWORK_ZONE", "INTERNAL"),
		DevelopmentInsecureTLS: boolean("NETSCOPE_DEVELOPMENT_INSECURE_TLS", false),
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	for _, d := range []string{"identity", "spool", "temp", "state"} {
		if err := os.MkdirAll(filepath.Join(c.DataDir, d), 0o700); err != nil {
			return Config{}, fmt.Errorf("create data directory: %w", err)
		}
	}
	return c, nil
}

func (c Config) Validate() error {
	u, err := url.Parse(c.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("NETSCOPE_CONTROL_PLANE_URL must be an absolute HTTPS URL")
	}
	if c.AgentName == "" || c.MaxConcurrentJobs < 1 || c.DefaultTimeout <= 0 || c.JobPollInterval <= 0 {
		return errors.New("invalid agent name, concurrency, timeout, or poll interval")
	}
	if c.ClientCertPath != "" || c.ClientKeyPath != "" {
		if c.ClientCertPath == "" || c.ClientKeyPath == "" {
			return errors.New("mTLS requires both client certificate and key")
		}
	}
	switch c.Zone {
	case "INTERNAL", "DMZ", "EXTERNAL_SENSOR", "LAB":
	default:
		return errors.New("NETSCOPE_NETWORK_ZONE is invalid")
	}
	return nil
}

func (c Config) TLSConfig() (*tls.Config, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.DevelopmentInsecureTLS} // #nosec G402: explicit dev-only escape hatch with critical logging.
	if c.CACertPath != "" {
		pem, err := os.ReadFile(c.CACertPath)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
		t.RootCAs = pool
	}
	if c.ClientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(c.ClientCertPath, c.ClientKeyPath)
		if err != nil {
			return nil, err
		}
		t.Certificates = []tls.Certificate{cert}
	}
	return t, nil
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func duration(k string, d time.Duration) time.Duration {
	v, err := time.ParseDuration(os.Getenv(k))
	if err == nil && v > 0 {
		return v
	}
	return d
}
func integer(k string, d int) int {
	v, err := strconv.Atoi(os.Getenv(k))
	if err == nil && v > 0 {
		return v
	}
	return d
}
func bytes(k string, d int64) int64 {
	v, err := strconv.ParseInt(os.Getenv(k), 10, 64)
	if err == nil && v > 0 {
		return v
	}
	return d
}
func boolean(k string, d bool) bool {
	v, err := strconv.ParseBool(os.Getenv(k))
	if err == nil {
		return v
	}
	return d
}
