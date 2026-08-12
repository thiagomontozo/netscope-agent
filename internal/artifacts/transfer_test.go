package artifacts

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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
