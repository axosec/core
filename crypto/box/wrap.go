package box

import (
	"crypto/ecdh"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = chacha20poly1305.KeySize

var (
	ErrInvalidKeySize = errors.New("key must be exactly 32 bytes")
	ErrUnwrapFailed   = errors.New("unwrapped data is not a valid key")
)

// WrapKey encrypts a symmetric key for a recipient.
func WrapKey(keyToShare []byte, recipientPub *ecdh.PublicKey) ([]byte, []byte, error) {
	if len(keyToShare) != KeySize {
		return nil, nil, ErrInvalidKeySize
	}

	return Seal(keyToShare, recipientPub)
}

// UnwrapKey decrypts a wrapped key using your private key.
func UnwrapKey(wrappedBlob, nonce []byte, myPriv *ecdh.PrivateKey) ([]byte, error) {
	decryptedData, err := Unseal(wrappedBlob, nonce, myPriv)
	if err != nil {
		return nil, fmt.Errorf("unwrap failed: %w", err)
	}

	if len(decryptedData) != KeySize {
		return nil, ErrUnwrapFailed
	}

	return decryptedData, nil
}
