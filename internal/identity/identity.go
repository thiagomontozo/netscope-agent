package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
	"github.com/thiagomontozo/netscope-agent/internal/security"
)

const (
	metadataFile = "metadata.json"
	privateFile  = "client-private-key.pem"
	certFile     = "client-certificate.pem"
	trustFile    = "control-plane-agent-ca.pem"
	signingFile  = "control-plane-job-signing-key"
)

type Identity struct {
	AgentID               string    `json:"agentId"`
	OrganizationID        string    `json:"organizationId"`
	ProtocolVersion       string    `json:"protocolVersion"`
	CertificateExpiry     time.Time `json:"certificateExpiry"`
	Fingerprint           string    `json:"fingerprint"`
	SigningKeyID          string    `json:"signingKeyId,omitempty"`
	SigningKeyFingerprint string    `json:"signingKeyFingerprint,omitempty"`
	DataDir               string    `json:"-"`
}

type Pending struct {
	PrivateKeyPEM []byte
	CSRPEM        string
}

func directory(dataDir string) string  { return filepath.Join(dataDir, "identity") }
func Path(dataDir, name string) string { return filepath.Join(directory(dataDir), name) }

func Generate(agentName, hostname string) (Pending, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Pending{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Pending{}, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentName}}
	if hostname != "" {
		template.DNSNames = []string{hostname}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return Pending{}, err
	}
	return Pending{PrivateKeyPEM: privatePEM, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))}, nil
}

func SaveEnrollment(dataDir string, pending Pending, response protocol.EnrollmentResponse) (*Identity, error) {
	if response.AgentID == "" || response.OrganizationID == "" || response.AgentCredential.CertificatePEM == "" || response.ControlPlaneIdentity.CACertificatePEM == "" {
		return nil, errors.New("enrollment response omitted required identity material")
	}
	if err := protocol.RequireCompatible(response.ProtocolVersion); err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair([]byte(response.AgentCredential.CertificatePEM), pending.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("enrollment certificate does not match local key: %w", err)
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	expiryDifference := response.AgentCredential.ExpiresAt.Sub(certificate.NotAfter)
	if expiryDifference < 0 {
		expiryDifference = -expiryDifference
	}
	if time.Now().UTC().After(certificate.NotAfter) || expiryDifference >= time.Second {
		return nil, errors.New("enrollment certificate expiry is invalid")
	}
	digest := sha256.Sum256(certificate.Raw)
	id := &Identity{AgentID: response.AgentID, OrganizationID: response.OrganizationID, ProtocolVersion: response.ProtocolVersion, CertificateExpiry: certificate.NotAfter, Fingerprint: hex.EncodeToString(digest[:]), SigningKeyID: response.ControlPlaneIdentity.JobSigningKeyID, SigningKeyFingerprint: response.ControlPlaneIdentity.JobSigningKeyFingerprint, DataDir: dataDir}
	metadata, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return nil, err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{privateFile, pending.PrivateKeyPEM, 0o600},
		{certFile, []byte(response.AgentCredential.CertificatePEM), 0o600},
		{trustFile, []byte(response.ControlPlaneIdentity.CACertificatePEM), 0o600},
	}
	if response.ControlPlaneIdentity.JobSigningPublicKey != "" {
		trusted := security.TrustedSigningKey{KeyID: response.ControlPlaneIdentity.JobSigningKeyID, Algorithm: response.ControlPlaneIdentity.JobSigningAlgorithm, PublicKey: response.ControlPlaneIdentity.JobSigningPublicKey, Fingerprint: response.ControlPlaneIdentity.JobSigningKeyFingerprint, IssuedAt: response.ControlPlaneIdentity.JobSigningKeyIssuedAt}
		if _, err := trusted.Decode(); err != nil {
			return nil, fmt.Errorf("enrollment signing trust is invalid: %w", err)
		}
		trustJSON, err := json.MarshalIndent([]security.TrustedSigningKey{trusted}, "", "  ")
		if err != nil {
			return nil, err
		}
		files = append(files, struct {
			name string
			data []byte
			mode os.FileMode
		}{signingFile, trustJSON, 0o600})
	}
	files = append(files, struct {
		name string
		data []byte
		mode os.FileMode
	}{metadataFile, metadata, 0o600})
	stage, err := os.MkdirTemp(dataDir, ".identity-stage-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return nil, err
	}
	for _, file := range files {
		if err := writeFile(filepath.Join(stage, file.name), file.data, file.mode); err != nil {
			return nil, err
		}
	}
	target := directory(dataDir)
	if entries, readErr := os.ReadDir(target); readErr == nil {
		if len(entries) != 0 {
			return nil, errors.New("identity directory is not empty; refusing to overwrite existing material")
		}
		if err := os.Remove(target); err != nil {
			return nil, err
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	if err := os.Rename(stage, target); err != nil {
		return nil, err
	}
	return id, nil
}

func Load(dataDir string) (*Identity, error) {
	metadata, err := os.ReadFile(Path(dataDir, metadataFile))
	if errors.Is(err, os.ErrNotExist) {
		if entries, readErr := os.ReadDir(directory(dataDir)); readErr == nil && len(entries) > 0 {
			return nil, errors.New("legacy or partial identity material requires explicit administrative recovery")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(metadata, &id); err != nil {
		return nil, fmt.Errorf("decode identity metadata: %w", err)
	}
	id.DataDir = dataDir
	if id.AgentID == "" || id.OrganizationID == "" || protocol.RequireCompatible(id.ProtocolVersion) != nil {
		return nil, errors.New("stored identity is incomplete or protocol-incompatible")
	}
	pair, certificate, err := id.keyPair()
	if err != nil {
		return nil, err
	}
	_ = pair
	if time.Now().UTC().After(certificate.NotAfter) {
		return nil, errors.New("agent client certificate has expired")
	}
	digest := sha256.Sum256(certificate.Raw)
	if id.Fingerprint != hex.EncodeToString(digest[:]) {
		return nil, errors.New("agent certificate fingerprint does not match metadata")
	}
	return &id, nil
}

func (i Identity) TLSCertificate() (tls.Certificate, error) {
	pair, _, err := i.keyPair()
	return pair, err
}

func (i Identity) keyPair() (tls.Certificate, *x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(Path(i.DataDir, certFile), Path(i.DataDir, privateFile))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	return pair, certificate, err
}

func SigningKeyPath(dataDir string) string { return Path(dataDir, signingFile) }

func TrustedSigningKeys(dataDir string) (map[string]ed25519.PublicKey, error) {
	encoded, err := os.ReadFile(SigningKeyPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]ed25519.PublicKey{}, nil
	}
	if err != nil {
		return nil, err
	}
	var records []security.TrustedSigningKey
	if err := json.Unmarshal(encoded, &records); err != nil {
		return nil, errors.New("stored signing trust is invalid")
	}
	keys := make(map[string]ed25519.PublicKey, len(records))
	for _, record := range records {
		key, err := record.Decode()
		if err != nil {
			return nil, err
		}
		if _, duplicate := keys[record.KeyID]; duplicate {
			return nil, errors.New("duplicate signing key ID")
		}
		keys[record.KeyID] = key
	}
	return keys, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
