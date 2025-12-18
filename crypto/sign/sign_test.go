package sign_test

import (
	"testing"

	"github.com/axosec/core/crypto/sign"
)

func TestIdentityFlow(t *testing.T) {
	kp, err := sign.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	pemData := kp.PrivateToPEM()
	loadedKp, err := sign.LoadPrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to load PEM: %v", err)
	}

	signer := sign.NewSigner()
	msg := []byte("User_123_Login_Request_Nonce_998877")

	signature := signer.Sign(msg, loadedKp.Private)

	isValid := signer.Verify(msg, signature, kp.Public)
	if !isValid {
		t.Fatal("Signature verification failed")
	}
}

func TestTampering(t *testing.T) {
	kp, _ := sign.GenerateKeyPair()
	signer := sign.NewSigner()
	msg := []byte("Pay $100")
	sig := signer.Sign(msg, kp.Private)

	if signer.Verify([]byte("Pay $900"), sig, kp.Public) {
		t.Fatal("Verified tampered message!")
	}

	sig[0] ^= 0xFF 
	if signer.Verify(msg, sig, kp.Public) {
		t.Fatal("Verified tampered signature!")
	}
}
