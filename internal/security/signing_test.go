package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

func signedTestEnvelope() protocol.JobEnvelope {
	return protocol.JobEnvelope{ProtocolVersion: "1.0", JobID: "33333333-3333-4333-8333-333333333333", OrganizationID: "22222222-2222-4222-8222-222222222222", AgentID: "11111111-1111-4111-8111-111111111111", ModuleID: "mock.safe", ModuleVersionRequirement: "1.0.0", ScopeID: "44444444-4444-4444-8444-444444444444", ScopeEnvironment: "INTERNAL", Target: protocol.JobTarget{Type: "HOSTNAME", Value: "fixture.test.invalid"}, ValidatedParameters: []byte(`{"z":2,"mode":"synthetic","nested":{"b":true,"a":null}}`), RiskClass: protocol.RiskPassive, AuthorizationReference: "test-only:fixture", IssuedAt: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 11, 12, 5, 0, 0, time.UTC), TimeoutSeconds: 30, Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SigningKeyID: "test-only-2026-08", SignatureAlgorithm: SignatureAlgorithmEd25519}
}

func TestCanonicalPayloadMatchesControlPlane(t *testing.T) {
	payload, err := CanonicalJobPayload(signedTestEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agentId":"11111111-1111-4111-8111-111111111111","authorizationReference":"test-only:fixture","expiresAt":"2026-08-11T12:05:00Z","issuedAt":"2026-08-11T12:00:00Z","jobId":"33333333-3333-4333-8333-333333333333","moduleId":"mock.safe","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","organizationId":"22222222-2222-4222-8222-222222222222","protocolVersion":"1.0","riskClass":"PASSIVE","scopeEnvironment":"INTERNAL","scopeId":"44444444-4444-4444-8444-444444444444","target":{"type":"HOSTNAME","value":"fixture.test.invalid"},"timeoutSeconds":30,"validatedParameters":{"mode":"synthetic","nested":{"a":null,"b":true},"z":2}}`
	if string(payload) != want {
		t.Fatalf("canonical payload mismatch: %s", payload)
	}
}

func TestVerifySignedJobAndRejectTamper(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	job := signedTestEnvelope()
	payload, _ := CanonicalJobPayload(job)
	job.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	keys := map[string]ed25519.PublicKey{job.SigningKeyID: public}
	if err := VerifyJobSignature(job, keys); err != nil {
		t.Fatal(err)
	}
	job.Target.Value = "tampered.test.invalid"
	if err := VerifyJobSignature(job, keys); err == nil {
		t.Fatal("tampered job signature was accepted")
	}
}
