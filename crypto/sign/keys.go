package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
)

type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKeyPair creates a new random Ed25519 identity key.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}
	return &KeyPair{
		Public:  pub,
		Private: priv,
	}, nil
}

// Bytes returns the raw bytes.
func (k *KeyPair) Bytes() ([]byte, []byte) {
	return k.Private, k.Public
}

// ToPEM encodes the private key to a PEM block.
func (k *KeyPair) PrivateToPEM() []byte {
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: k.Private,
	}
	return pem.EncodeToMemory(block)
}

// PublicToPEM encodes the public key to PEM.
func (k *KeyPair) PublicToPEM() []byte {
	block := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: k.Public,
	}
	return pem.EncodeToMemory(block)
}

// LoadPrivateKeyFromPEM parses a PEM block back into a KeyPair.
// Derives the public key from the private key automatically.
func LoadPrivateKeyFromPEM(pemBytes []byte) (*KeyPair, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size: wanted %d, got %d", ed25519.PrivateKeySize, len(block.Bytes))
	}

	priv := ed25519.PrivateKey(block.Bytes)
	pub := priv.Public().(ed25519.PublicKey)

	return &KeyPair{
		Public:  pub,
		Private: priv,
	}, nil
}
