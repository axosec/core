package box

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

type KeyPair struct {
	Public  *ecdh.PublicKey
	Private *ecdh.PrivateKey
}

// GenerateKeyPair creates a fresh X25519 identity for encryption.
func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}

	return &KeyPair{
		Public:  priv.PublicKey(),
		Private: priv,
	}, nil
}

// Bytes returns the raw 32-byte keys. 
func (k *KeyPair) Bytes() ([]byte, []byte) {
	return k.Private.Bytes(), k.Public.Bytes()
}

// LoadPrivateKey converts raw bytes into a usable Key Pair object.
func LoadPrivateKey(privBytes []byte) (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key bytes: %w", err)
	}
	return &KeyPair{
		Public:  priv.PublicKey(),
		Private: priv,
	}, nil
}

// LoadPublicKey converts raw bytes back into a Public Key object.
func LoadPublicKey(pubBytes []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(pubBytes)
}
