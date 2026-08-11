package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/thiagomontozo/netscope-agent/internal/protocol"
)

func NewManifest(source, summary, artifactKind string, structured map[string]any) (protocol.EvidenceManifest, error) {
	if source == "" || summary == "" || structured == nil {
		return protocol.EvidenceManifest{}, errors.New("evidence source, summary and structured data are required")
	}
	data, err := json.Marshal(structured)
	if err != nil {
		return protocol.EvidenceManifest{}, err
	}
	digest := sha256.Sum256(data)
	id, err := NewID()
	if err != nil {
		return protocol.EvidenceManifest{}, err
	}
	return protocol.EvidenceManifest{EvidenceID: id, Source: source, ContentType: "application/json", Summary: summary, StructuredData: data, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data)), ArtifactKind: artifactKind}, nil
}

func NewID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
