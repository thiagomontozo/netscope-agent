package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSyntheticArtifactDownloadMockProcessAndUpload(t *testing.T) {
	input := []byte("TEST ONLY synthetic artifact\n")
	inputDigest := sha256.Sum256(input)
	output := []byte(strings.ToUpper(string(input)))
	outputDigest := sha256.Sum256(output)
	uploaded := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if r.Header.Get("Authorization") != "Artifact download-token" {
				t.Error("download token missing")
			}
			_, _ = w.Write(input)
		case http.MethodPut:
			if r.Header.Get("Authorization") != "Artifact upload-token" || r.Header.Get("X-NetScope-Artifact-SHA256") != hex.EncodeToString(outputDigest[:]) {
				t.Error("upload authorization or checksum metadata mismatch")
			}
			body, _ := io.ReadAll(r.Body)
			uploaded <- body
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	transfer := Transfer{HTTP: server.Client(), MaxDownloadBytes: 1024, MaxUploadBytes: 1024, TempDir: t.TempDir()}
	inputPath, err := transfer.Download(context.Background(), server.URL, "download-token", "input-artifact", int64(len(input)), hex.EncodeToString(inputDigest[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(inputPath)
	// This is a safe in-process mock module: no scanner or external process.
	read, _ := os.ReadFile(inputPath)
	outputPath := t.TempDir() + string(os.PathSeparator) + "output-artifact"
	if err := os.WriteFile(outputPath, []byte(strings.ToUpper(string(read))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transfer.Upload(context.Background(), server.URL, "upload-token", outputPath, hex.EncodeToString(outputDigest[:])); err != nil {
		t.Fatal(err)
	}
	if got := <-uploaded; string(got) != string(output) {
		t.Fatal("uploaded mock output differs from expected synthetic artifact")
	}
}
