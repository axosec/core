package box

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/axosec/core/crypto/vault"
)

func deriveSharedKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh calculation failed: %w", err)
	}

	key := sha512.Sum512_256(secret)
	return key[:], nil
}

// Seal encrypts a message anonymously.
// It generates an temporary key pair, so the sender does not need an identity.
//
// Output Structure: [EphemeralPublicKey (32 bytes)] + [VaultBlob (Nonce + Ciphertext)]
func Seal(plaintext []byte, recipientPub *ecdh.PublicKey) ([]byte, error) {
	curve := ecdh.X25519()
	tempPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	sharedKey, err := deriveSharedKey(tempPriv, recipientPub)
	if err != nil {
		return nil, err
	}

	encryptedData, err := vault.Encrypt(plaintext, sharedKey)
	if err != nil {
		return nil, err
	}

	return append(tempPriv.PublicKey().Bytes(), encryptedData...), nil
}

// Unseal decrypts an anonymously encrypted message.
// It extracts the temprorary public key from the header and uses it to derive the decryption key.
func Unseal(data []byte, recipientPriv *ecdh.PrivateKey) ([]byte, error) {
	pubKeyLength := 32
	if len(data) <= pubKeyLength {
		return nil, errors.New("message too short")
	}

	senderPubBytes := data[:pubKeyLength]

	ciphertext := data[pubKeyLength:]

	senderPubKey, err := LoadPublicKey(senderPubBytes)
	if err != nil {
		return nil, err
	}

	return Decrypt(ciphertext, recipientPriv, senderPubKey)
}

// Encrypt encrypts data using sernder's private key and recipient's public key pair.
func Encrypt(plaintext []byte, senderPriv *ecdh.PrivateKey, recipientPub *ecdh.PublicKey) ([]byte, error) {
	sharedKey, err := deriveSharedKey(senderPriv, recipientPub)
	if err != nil {
		return nil, err
	}

	return vault.Encrypt(plaintext, sharedKey)
}

// Decrypt decrypts data using recipient's private key and sender's public key pair.
func Decrypt(ciphertext []byte, recipientPriv *ecdh.PrivateKey, senderPub *ecdh.PublicKey) ([]byte, error) {
	sharedKey, err := deriveSharedKey(recipientPriv, senderPub)
	if err != nil {
		return nil, err
	}

	return vault.Decrypt(ciphertext, sharedKey)
}
