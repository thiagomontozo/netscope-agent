package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDownloadStreamsSyntheticArtifact(t *testing.T) {
	content := []byte("TEST ONLY synthetic artifact\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(content) }))
	defer server.Close()
	transfer := Transfer{HTTP: server.Client(), MaxDownloadBytes: 1024, MaxUploadBytes: 1024, TempDir: t.TempDir()}
	path, err := transfer.Download(context.Background(), server.URL, "test-only-token", "artifact-1", int64(len(content)), "5154c4cb28216a86aea7175641f5270dc02fd1876652d29d56a62cff9dde1173")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	read, _ := os.ReadFile(path)
	if string(read) != string(content) {
		t.Fatal("downloaded artifact changed")
	}
}

func TestDownloadRejectsChecksumMismatch(t *testing.T) {
	content := []byte("TEST ONLY synthetic artifact\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(content) }))
	defer server.Close()
	transfer := Transfer{HTTP: server.Client(), MaxDownloadBytes: 1024, TempDir: t.TempDir()}
	_, err := transfer.Download(context.Background(), server.URL, "test-only-token", "artifact-1", int64(len(content)), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestUploadStreamsAndVerifiesSyntheticArtifact(t *testing.T) {
	content := []byte("TEST ONLY synthetic upload artifact\n")
	digest := sha256.Sum256(content)
	directory := t.TempDir()
	path := directory + string(os.PathSeparator) + "artifact.txt"
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.Header.Get("Authorization") != "Artifact test-only-token" {
			t.Error("upload request metadata mismatch")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != string(content) {
			t.Error("streamed upload body mismatch")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	transfer := Transfer{HTTP: server.Client(), MaxUploadBytes: 1024}
	if err := transfer.Upload(context.Background(), server.URL, "test-only-token", path, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := transfer.Upload(context.Background(), server.URL, "test-only-token", path, strings.Repeat("a", 64)); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected local checksum mismatch, got %v", err)
	}
}

func TestTransferLimitsAndPartialDownloadCleanup(t *testing.T) {
	temp := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("too-large")) }))
	defer server.Close()
	transfer := Transfer{HTTP: server.Client(), MaxDownloadBytes: 4, MaxUploadBytes: 4, TempDir: temp}
	if _, err := transfer.Download(context.Background(), server.URL, "token", "../../secret.txt", 9, strings.Repeat("a", 64)); !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("expected size rejection, got %v", err)
	}
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		t.Fatal("partial or path-derived file remained after rejected download")
	}
	path := temp + string(os.PathSeparator) + "oversized.txt"
	_ = os.WriteFile(path, []byte("12345"), 0o600)
	if err := transfer.Upload(context.Background(), server.URL, "token", path, strings.Repeat("a", 64)); !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("expected upload size rejection, got %v", err)
	}
}
