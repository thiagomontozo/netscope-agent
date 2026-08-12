package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type RotationResponse struct {
	CertificateID  string    `json:"certificateId"`
	CertificatePEM string    `json:"certificatePem"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Fingerprint    string    `json:"fingerprint"`
	SerialNumber   string    `json:"serialNumber"`
}

// StageRotation validates the certificate/key pair and writes it to a private,
// fsynced staging directory. ActivateRotation performs atomic renames while
// keeping a bounded rollback copy until the Control Plane confirms activation.
func StageRotation(dataDir string, pending Pending, response RotationResponse) (string, error) {
	if response.CertificateID == "" || response.CertificatePEM == "" {
		return "", errors.New("rotation response is incomplete")
	}
	pair, err := tls.X509KeyPair([]byte(response.CertificatePEM), pending.PrivateKeyPEM)
	if err != nil {
		return "", errors.New("rotation certificate does not match new local key")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", err
	}
	if time.Now().UTC().After(certificate.NotAfter) || certificate.NotAfter.Sub(response.ExpiresAt) >= time.Second || response.ExpiresAt.Sub(certificate.NotAfter) >= time.Second {
		return "", errors.New("rotation certificate expiry is invalid")
	}
	stage := filepath.Join(dataDir, "identity-rotation-"+response.CertificateID)
	if err := os.Mkdir(stage, 0o700); err != nil {
		return "", err
	}
	digest := sha256.Sum256(certificate.Raw)
	if hex.EncodeToString(digest[:]) != response.Fingerprint {
		_ = os.RemoveAll(stage)
		return "", errors.New("rotation certificate fingerprint mismatch")
	}
	current, err := Load(dataDir)
	if err != nil || current == nil {
		_ = os.RemoveAll(stage)
		return "", errors.New("active identity is unavailable for rotation")
	}
	current.CertificateExpiry = certificate.NotAfter
	current.Fingerprint = response.Fingerprint
	current.DataDir = ""
	metadata, _ := json.MarshalIndent(current, "", "  ")
	items := []struct {
		name string
		data []byte
	}{{privateFile, pending.PrivateKeyPEM}, {certFile, []byte(response.CertificatePEM)}, {metadataFile, metadata}}
	for _, preserved := range []string{trustFile, signingFile} {
		data, readErr := os.ReadFile(Path(dataDir, preserved))
		if readErr != nil {
			_ = os.RemoveAll(stage)
			return "", readErr
		}
		items = append(items, struct {
			name string
			data []byte
		}{preserved, data})
	}
	for _, item := range items {
		if err := writeFile(filepath.Join(stage, item.name), item.data, 0o600); err != nil {
			_ = os.RemoveAll(stage)
			return "", err
		}
	}
	return stage, nil
}

func ActivateRotation(dataDir, stage string) error {
	if filepath.Dir(stage) != filepath.Clean(dataDir) {
		return errors.New("rotation staging path is outside data directory")
	}
	active := directory(dataDir)
	rollback := filepath.Join(dataDir, "identity-rollback")
	if _, err := os.Stat(rollback); err == nil {
		return errors.New("a prior rotation rollback remains pending")
	}
	if err := os.Rename(active, rollback); err != nil {
		return err
	}
	if err := os.Rename(stage, active); err != nil {
		_ = os.Rename(rollback, active)
		return err
	}
	return nil
}

func RollbackRotation(dataDir string) error {
	active := directory(dataDir)
	rollback := filepath.Join(dataDir, "identity-rollback")
	failed := filepath.Join(dataDir, "identity-rotation-failed")
	if err := os.Rename(active, failed); err != nil {
		return err
	}
	if err := os.Rename(rollback, active); err != nil {
		_ = os.Rename(failed, active)
		return err
	}
	return os.RemoveAll(failed)
}

func CommitRotation(dataDir string) error {
	return os.RemoveAll(filepath.Join(dataDir, "identity-rollback"))
}

func parseCertificatePEM(value string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("certificate PEM is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}
