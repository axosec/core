package vault_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/axosec/core/crypto/vault"
)

func TestVault_RoundTrip(t *testing.T) {
	key := make([]byte, vault.KeySize)
	rand.Read(key)

	secret := []byte("This is a highly sensitive string.")

	encrypted, nonce, err := vault.Encrypt(secret, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := vault.Decrypt(encrypted, nonce, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(secret, decrypted) {
		t.Errorf("Mismatch! Got %s, want %s", decrypted, secret)
	}
}

func TestVault_TamperDetect(t *testing.T) {
	key := make([]byte, vault.KeySize)
	rand.Read(key)
	encrypted, nonce, _ := vault.Encrypt([]byte("data"), key)

	encrypted[len(encrypted)-1] ^= 0xFF

	_, err := vault.Decrypt(encrypted, nonce, key)
	if err == nil {
		t.Fatal("Security Fail: Decrypted tampered data without error!")
	}
}

func TestVault_WrongKey(t *testing.T) {
	key1 := make([]byte, vault.KeySize)
	key2 := make([]byte, vault.KeySize)
	rand.Read(key1)
	rand.Read(key2)

	encrypted, nonce, _ := vault.Encrypt([]byte("data"), key1)

	_, err := vault.Decrypt(encrypted, nonce, key2)
	if err == nil {
		t.Fatal("Security Fail: Decrypted with wrong key!")
	}
}
