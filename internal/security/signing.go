package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/thiagomontozo/netscope-agent/internal/canonicaljson"
	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

const SignatureAlgorithmEd25519 = "Ed25519"

type TrustedSigningKey struct {
	KeyID       string    `json:"keyId"`
	Algorithm   string    `json:"algorithm"`
	PublicKey   string    `json:"publicKey"`
	Fingerprint string    `json:"fingerprint"`
	IssuedAt    time.Time `json:"issuedAt"`
}

func (key TrustedSigningKey) Decode() (ed25519.PublicKey, error) {
	if key.KeyID == "" || key.Algorithm != SignatureAlgorithmEd25519 {
		return nil, errors.New("trusted signing key metadata is invalid")
	}
	decoded, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("trusted signing public key is invalid")
	}
	digest := sha256.Sum256(decoded)
	if key.Fingerprint != hex.EncodeToString(digest[:]) {
		return nil, errors.New("trusted signing key fingerprint mismatch")
	}
	return ed25519.PublicKey(decoded), nil
}

func VerifyJobSignature(job protocol.JobEnvelope, keys map[string]ed25519.PublicKey) error {
	if job.SigningKeyID == "" || job.SignatureAlgorithm != SignatureAlgorithmEd25519 || job.Signature == "" {
		return errors.New("signed job metadata is incomplete")
	}
	key, ok := keys[job.SigningKeyID]
	if !ok {
		return errors.New("job signing key is not trusted")
	}
	signature, err := base64.StdEncoding.DecodeString(job.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("job signature encoding is invalid")
	}
	payload, err := CanonicalJobPayload(job)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, payload, signature) {
		return errors.New("job signature verification failed")
	}
	return nil
}

func CanonicalJobPayload(job protocol.JobEnvelope) ([]byte, error) {
	parameters, err := canonicaljson.Canonicalize(job.ValidatedParameters)
	if err != nil {
		return nil, fmt.Errorf("decode validated parameters: %w", err)
	}
	payload := map[string]any{
		"agentId": job.AgentID, "authorizationReference": job.AuthorizationReference,
		"expiresAt": job.ExpiresAt.UTC().Format(time.RFC3339Nano), "issuedAt": job.IssuedAt.UTC().Format(time.RFC3339Nano),
		"jobId": job.JobID, "moduleId": job.ModuleID, "nonce": job.Nonce,
		"organizationId": job.OrganizationID, "protocolVersion": job.ProtocolVersion,
		"riskClass": job.RiskClass, "scopeEnvironment": job.ScopeEnvironment, "scopeId": job.ScopeID,
		"target":         map[string]any{"type": job.Target.Type, "value": job.Target.Value},
		"timeoutSeconds": job.TimeoutSeconds, "validatedParameters": json.RawMessage(parameters),
	}
	if job.AssetID != nil {
		payload["assetId"] = *job.AssetID
	}
	if job.ServiceID != nil {
		payload["serviceId"] = *job.ServiceID
	}
	return canonicaljson.Marshal(payload)
}
