package vault

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = chacha20poly1305.KeySize

// Encrypt encrypts data using XChaCha20-Poly1305.
// Returns the ciphertext and the randomly generated nonce separately.
//
// Output: ciphertext ([]byte), nonce ([]byte), error
func Encrypt(plaintext []byte, key []byte) ([]byte, []byte, error) {
	if len(key) != KeySize {
		return nil, nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// Decrypt decrypts data using XChaCha20-Poly1305.
func Decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), KeySize)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d, want %d", len(nonce), aead.NonceSize())
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}
