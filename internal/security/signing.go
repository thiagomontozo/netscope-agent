package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

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
	var parameters any
	decoder := json.NewDecoder(bytes.NewReader(job.ValidatedParameters))
	decoder.UseNumber()
	if err := decoder.Decode(&parameters); err != nil {
		return nil, fmt.Errorf("decode validated parameters: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("validated parameters contain trailing JSON")
	}
	payload := map[string]any{
		"agentId": job.AgentID, "authorizationReference": job.AuthorizationReference,
		"expiresAt": job.ExpiresAt.UTC().Format(time.RFC3339Nano), "issuedAt": job.IssuedAt.UTC().Format(time.RFC3339Nano),
		"jobId": job.JobID, "moduleId": job.ModuleID, "nonce": job.Nonce,
		"organizationId": job.OrganizationID, "protocolVersion": job.ProtocolVersion,
		"riskClass": job.RiskClass, "scopeEnvironment": job.ScopeEnvironment, "scopeId": job.ScopeID,
		"target":         map[string]any{"type": job.Target.Type, "value": job.Target.Value},
		"timeoutSeconds": job.TimeoutSeconds, "validatedParameters": parameters,
	}
	if job.AssetID != nil {
		payload["assetId"] = *job.AssetID
	}
	if job.ServiceID != nil {
		payload["serviceId"] = *job.ServiceID
	}
	var output bytes.Buffer
	if err := writeCanonical(&output, payload); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		encoded, _ := json.Marshal(typed)
		output.Write(encoded)
	case protocol.RiskClass:
		encoded, _ := json.Marshal(string(typed))
		output.Write(encoded)
	case int:
		output.WriteString(strconv.Itoa(typed))
	case json.Number:
		if strings.ContainsAny(string(typed), ".eE") {
			return errors.New("signed job parameters must use integer JSON numbers")
		}
		if _, err := strconv.ParseInt(string(typed), 10, 64); err != nil {
			return errors.New("invalid signed job integer")
		}
		output.WriteString(string(typed))
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			output.Write(encoded)
			output.WriteByte(':')
			if err := writeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		var normalized any
		if err := decoder.Decode(&normalized); err != nil {
			return err
		}
		return writeCanonical(output, normalized)
	}
	return nil
}
