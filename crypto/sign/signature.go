package sign

import "crypto/ed25519"

type Signer struct{}

func NewSigner() *Signer {
	return &Signer{}
}

// Sign creates a digital signature for the message.
func (s *Signer) Sign(message []byte, privateKey ed25519.PrivateKey) []byte {
	return ed25519.Sign(privateKey, message)
}

// Verify checks if the signature is valid for the given message and public key.
func (s *Signer) Verify(message []byte, signature []byte, publicKey ed25519.PublicKey) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}
