package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Identity struct {
	AgentID    string `json:"agentId"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	Credential string `json:"credential,omitempty"`
}

func Path(dataDir string) string { return filepath.Join(dataDir, "identity", "identity.json") }

func Load(dataDir string) (*Identity, error) {
	b, err := os.ReadFile(Path(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if id.AgentID == "" || id.PrivateKey == "" {
		return nil, errors.New("identity is incomplete")
	}
	return &id, nil
}

func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{PublicKey: base64.RawStdEncoding.EncodeToString(pub), PrivateKey: base64.RawStdEncoding.EncodeToString(priv)}, nil
}

func Save(dataDir string, id *Identity) error {
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	p := Path(dataDir)
	tmp, err := os.CreateTemp(filepath.Dir(p), ".identity-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, p)
}

func (i Identity) Authorization() string { return "Agent " + i.Credential }
