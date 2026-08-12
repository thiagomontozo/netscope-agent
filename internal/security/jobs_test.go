package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

func signTestJob(t *testing.T, job protocol.JobEnvelope) (protocol.JobEnvelope, ed25519.PublicKey) {
	t.Helper()
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	private := ed25519.NewKeyFromSeed(seed)
	payload, err := CanonicalJobPayload(job)
	if err != nil {
		t.Fatal(err)
	}
	job.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))
	return job, private.Public().(ed25519.PublicKey)
}

func TestJobVerifierSecurityInvariants(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 1, 0, 0, time.UTC)
	base := signedTestEnvelope()
	signed, key := signTestJob(t, base)
	newVerifier := func(agent string) *JobVerifier {
		return &JobVerifier{AgentID: agent, OrganizationID: base.OrganizationID, Now: func() time.Time { return now }, RequireSigned: true, TrustedKeys: map[string]ed25519.PublicKey{base.SigningKeyID: key}}
	}
	verifier := newVerifier(base.AgentID)
	if err := verifier.Verify(signed); err != nil {
		t.Fatalf("valid signed job rejected: %v", err)
	}
	if err := verifier.Verify(signed); FailureCode(err) != protocol.FailureReplay {
		t.Fatalf("replayed nonce failure=%v", err)
	}
	tampered := signed
	tampered.Target.Value = "changed.test.invalid"
	if err := newVerifier(base.AgentID).Verify(tampered); FailureCode(err) != protocol.FailureSignature {
		t.Fatalf("tamper failure=%v", err)
	}
	unknownKey := signed
	unknownKey.SigningKeyID = "unknown-test-key"
	if err := newVerifier(base.AgentID).Verify(unknownKey); FailureCode(err) != protocol.FailureSignature {
		t.Fatalf("unknown signing key failure=%v", err)
	}
	if err := newVerifier("99999999-9999-4999-8999-999999999999").Verify(signed); FailureCode(err) != protocol.FailureInvalidJob {
		t.Fatalf("wrong agent failure=%v", err)
	}
	expired := base
	expired.ExpiresAt = now.Add(-time.Second)
	expired, _ = signTestJob(t, expired)
	if err := newVerifier(base.AgentID).Verify(expired); FailureCode(err) != protocol.FailureJobExpired {
		t.Fatalf("expired failure=%v", err)
	}
	unsigned := base
	unsigned.SigningKeyID = ""
	unsigned.SignatureAlgorithm = ""
	if err := newVerifier(base.AgentID).Verify(unsigned); FailureCode(err) != protocol.FailureSignature {
		t.Fatalf("unsigned failure=%v", err)
	}
	badMajor := base
	badMajor.ProtocolVersion = "2.0"
	badMajor, _ = signTestJob(t, badMajor)
	if err := newVerifier(base.AgentID).Verify(badMajor); FailureCode(err) != protocol.FailureProtocol {
		t.Fatalf("protocol failure=%v", err)
	}
	var verification *VerificationError
	if !errors.As(newVerifier(base.AgentID).Verify(unsigned), &verification) {
		t.Fatal("failure was not typed")
	}
}
