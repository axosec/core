package hash_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/axosec/core/crypto/hash"
)

func TestArgon2id_Workflow(t *testing.T) {
	password := "myPassword123*"

	encoded, err := hash.Create(password)
	if err != nil {
		t.Fatalf("Failed to create hash: %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Errorf("Hash format incorrect, got: %s", encoded)
	}

	match, err := hash.Verify(password, encoded)
	if err != nil {
		t.Fatalf("Verify failed with error: %v", err)
	}
	if !match {
		t.Fatal("Verify returned false for correct password")
	}

	match, err = hash.Verify("WrongPassword123", encoded)
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Fatal("Verify returned true for WRONG password!")
	}
}

func TestArgon2id_TamperedHash(t *testing.T) {
	password := "password"
	encoded, _ := hash.Create(password)

	parts := strings.Split(encoded, "$")
	parts[4] = "A" + parts[4][1:]
	tampered := strings.Join(parts, "$")

	match, _ := hash.Verify(password, tampered)
	if match {
		t.Fatal("Accepted tampered hash!")
	}
}


func TestDeriveKey_Simple(t *testing.T) {
	password := "pw"
	salt := []byte("0123456789abcdef")

	k1, err := hash.DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}

	k2, err := hash.DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("expected deterministic derived key for same password+salt")
	}

	if _, err := hash.DeriveKey(password, []byte("short")); err == nil {
		t.Fatal("expected error for invalid salt length, got nil")
	}

	salt2 := []byte("fedcba9876543210")
	k3, err := hash.DeriveKey(password, salt2)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if bytes.Equal(k1, k3) {
		t.Fatal("expected different keys derived for different salts")
	}
}
