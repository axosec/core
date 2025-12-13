package box_test

import (
	"bytes"
	"testing"

	"github.com/axosec/core/crypto/box"
)

func TestAuthenticatedFlow(t *testing.T) {
	alice, err := box.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice keys: %v", err)
	}
	bob, err := box.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob keys: %v", err)
	}

	message := []byte("Hey, this is a secret message! Don't leak it!")
	ciphertext, err := box.Encrypt(message, alice.Private, bob.Public)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	plaintext, err := box.Decrypt(ciphertext, bob.Private, alice.Public)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("Mismatch!\nWant: %s\nGot:  %s", message, plaintext)
	}
}

func TestAnonymousFlow(t *testing.T) {
	server, err := box.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Here is my anonymous tip.")
	sealedBox, err := box.Seal(message, server.Public)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	plaintext, err := box.Unseal(sealedBox, server.Private)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("Mismatch!\nWant: %s\nGot:  %s", message, plaintext)
	}
}

func TestTampering(t *testing.T) {
	alice, _ := box.GenerateKeyPair()
	bob, _ := box.GenerateKeyPair()
	
	msg := []byte("Sensitive Data")

	// Authenticated Encryption Tampering	
	encrypted, _ := box.Encrypt(msg, alice.Private, bob.Public)

	// Attack 1: Modify Ciphertext
	encrypted[len(encrypted)-1] ^= 0xFF
	_, err := box.Decrypt(encrypted, bob.Private, alice.Public)
	if err == nil {
		t.Error("Authenticated Decrypt should fail when ciphertext is modified")
	}

	// Attack 2: Wrong Sender (Spoofing)
	// Bob thinks the message came from Eve, not Alice.
	eve, _ := box.GenerateKeyPair()
	// Repair ciphertext first
	encrypted[len(encrypted)-1] ^= 0xFF 
	_, err = box.Decrypt(encrypted, bob.Private, eve.Public)
	if err == nil {
		t.Error("Decrypt should fail when specifying the wrong sender public key")
	}

	// Sealed Box Tampering	
	sealed, _ := box.Seal(msg, bob.Public)

	sealed[0] ^= 0xFF
	_, err = box.Unseal(sealed, bob.Private)
	if err == nil {
		t.Error("Unseal should fail when ephemeral key is modified")
	}
}

func TestWrongRecipient(t *testing.T) {
	alice, _ := box.GenerateKeyPair()
	bob, _ := box.GenerateKeyPair() 
	eve, _ := box.GenerateKeyPair()

	msg := []byte("For Bob Only")
	
	ciphertext, _ := box.Encrypt(msg, alice.Private, bob.Public)

	_, err := box.Decrypt(ciphertext, eve.Private, alice.Public)
	if err == nil {
		t.Fatal("Security Breach: Eve successfully decrypted Bob's message!")
	}
}

func TestEmptyMessage(t *testing.T) {
	alice, _ := box.GenerateKeyPair()
	bob, _ := box.GenerateKeyPair()

	empty := []byte("")
	
	// Authenticated
	ct, err := box.Encrypt(empty, alice.Private, bob.Public)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := box.Decrypt(ct, bob.Private, alice.Public)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Error("Expected empty result")
	}

	// Sealed
	st, err := box.Seal(empty, bob.Public)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := box.Unseal(st, bob.Private)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt2) != 0 {
		t.Error("Expected empty result")
	}
}
