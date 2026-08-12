package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

func TestStageRotationRejectsInvalidCertificate(t *testing.T) {
	pending, err := Generate("test-agent", "agent.test.invalid")
	if err != nil {
		t.Fatal(err)
	}
	_, err = StageRotation(t.TempDir(), pending, RotationResponse{CertificateID: "test-only", CertificatePEM: "not a certificate"})
	if err == nil {
		t.Fatal("invalid rotation certificate was accepted")
	}
}

func TestActivateRotationRejectsExternalStage(t *testing.T) {
	if err := ActivateRotation(t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("external staging directory was accepted")
	}
}

func TestStageRotationRejectsPathLikeCertificateIDBeforeWriting(t *testing.T) {
	dataDir := t.TempDir()
	pending, _ := Generate("test-agent", "")
	if _, err := StageRotation(dataDir, pending, RotationResponse{CertificateID: "../../identity", CertificatePEM: "not-used"}); err == nil {
		t.Fatal("path-like certificate ID was accepted")
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid certificate ID created staging files")
	}
}

func TestCertificateRotationHappyPathKeepsPrivateKeyLocal(t *testing.T) {
	dataDir, ca := enrolledTestIdentity(t)
	before, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := Generate("test-agent", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pending.CSRPEM, "PRIVATE KEY") {
		t.Fatal("CSR exposed private key material")
	}
	response := ca.issue(t, pending, "77777777-7777-4777-8777-777777777777")
	stage, err := StageRotation(dataDir, pending, response)
	if err != nil {
		t.Fatal(err)
	}
	if err := ActivateRotation(dataDir, stage); err != nil {
		t.Fatal(err)
	}
	after, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Fingerprint == before.Fingerprint || after.Fingerprint != response.Fingerprint {
		t.Fatal("new certificate was not activated")
	}
	if err := CommitRotation(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dataDir + string(os.PathSeparator) + "identity-rollback"); !os.IsNotExist(err) {
		t.Fatal("rollback material was not cleaned after confirmation")
	}
}

func TestCertificateRotationRollbackPreservesPriorIdentity(t *testing.T) {
	dataDir, ca := enrolledTestIdentity(t)
	before, _ := Load(dataDir)
	pending, _ := Generate("test-agent", "")
	response := ca.issue(t, pending, "88888888-8888-4888-8888-888888888888")
	stage, err := StageRotation(dataDir, pending, response)
	if err != nil {
		t.Fatal(err)
	}
	if err := ActivateRotation(dataDir, stage); err != nil {
		t.Fatal(err)
	}
	if err := RollbackRotation(dataDir); err != nil {
		t.Fatal(err)
	}
	after, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Fingerprint != before.Fingerprint {
		t.Fatal("rollback did not restore certificate A")
	}
	if _, err := os.Stat(dataDir + string(os.PathSeparator) + "identity-rotation-failed"); !os.IsNotExist(err) {
		t.Fatal("failed rotation material was not cleaned")
	}
}

type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         string
}

func enrolledTestIdentity(t *testing.T) (string, testCA) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST ONLY NetScope CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	template.Raw = der
	ca := testCA{certificate: template, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	pending, _ := Generate("test-agent", "")
	issued := ca.issue(t, pending, "99999999-9999-4999-8999-999999999999")
	dataDir := t.TempDir()
	_, err = SaveEnrollment(dataDir, pending, protocol.EnrollmentResponse{ProtocolVersion: protocol.Version, AgentID: "11111111-1111-4111-8111-111111111111", OrganizationID: "22222222-2222-4222-8222-222222222222", AgentCredential: protocol.AgentCredential{CertificatePEM: issued.CertificatePEM, ExpiresAt: issued.ExpiresAt}, ControlPlaneIdentity: protocol.ControlPlaneIdentity{CACertificatePEM: ca.pem}})
	if err != nil {
		t.Fatal(err)
	}
	return dataDir, ca
}

func (ca testCA) issue(t *testing.T, pending Pending, id string) RotationResponse {
	t.Helper()
	block, _ := pem.Decode([]byte(pending.CSRPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatal("invalid test CSR")
	}
	now := time.Now().UTC()
	serial := big.NewInt(0).SetBytes([]byte(id))
	template := &x509.Certificate{SerialNumber: serial, Subject: csr.Subject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	return RotationResponse{CertificateID: id, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), ExpiresAt: template.NotAfter, Fingerprint: hex.EncodeToString(digest[:]), SerialNumber: serial.String()}
}
