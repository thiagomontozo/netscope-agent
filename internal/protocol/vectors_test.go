package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVendoredContractVectorChecksum(t *testing.T) {
	path := filepath.Join("..", "..", "contracts", "agent", "v1", "test-vectors", "canonical-job-payload.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.TrimSpace(data)
	var value any
	if json.Unmarshal(data, &value) != nil {
		t.Fatal("canonical vector is invalid JSON")
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != "b459c126b204a51dafa054490519d13fbdb41bcbd123afc38560afe79f6a9348" {
		t.Fatalf("vendored contract vector diverged: %s", got)
	}
}
