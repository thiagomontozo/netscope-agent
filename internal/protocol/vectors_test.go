package protocol

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestVendoredContractManifest(t *testing.T) {
	root := filepath.Join("..", "..", "contracts", "agent", "v1")
	manifest, err := os.Open(filepath.Join(root, "contract-manifest.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	defer manifest.Close()
	scanner := bufio.NewScanner(manifest)
	count := 0
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 2 {
			t.Fatal("contract manifest line is invalid")
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(parts[1])))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != parts[0] {
			t.Fatalf("vendored contract checksum mismatch: %s", parts[1])
		}
		count++
	}
	if scanner.Err() != nil || count != 14 {
		t.Fatalf("expected 14 pinned vectors, got %d: %v", count, scanner.Err())
	}
}
