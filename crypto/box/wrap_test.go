package box_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/axosec/core/crypto/box"
)

func TestKeyWrapping_Flow(t *testing.T) {
	bob, err := box.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	vaultKey := make([]byte, box.KeySize)
	if _, err := rand.Read(vaultKey); err != nil {
		t.Fatal(err)
	}

	wrappedBlob, err := box.WrapKey(vaultKey, bob.Public)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	unwrappedKey, err := box.UnwrapKey(wrappedBlob, bob.Private)
	if err != nil {
		t.Fatalf("UnwrapKey failed: %v", err)
	}

	if !bytes.Equal(vaultKey, unwrappedKey) {
		t.Error("Unwrapped key does not match original vault key")
	}
}

func TestKeyWrapping_SafetyChecks(t *testing.T) {
	bob, _ := box.GenerateKeyPair()

	shortKey := []byte("too short")
	_, err := box.WrapKey(shortKey, bob.Public)
	if err == nil {
		t.Error("WrapKey should fail if input is not 32 bytes")
	}

	garbage := make([]byte, 100)
	_, err = box.UnwrapKey(garbage, bob.Private)
	if err == nil {
		t.Error("UnwrapKey should fail on garbage data")
	}

	notAKey := make([]byte, 33)	
	malformedBox, _ := box.Seal(notAKey, bob.Public)
	
	_, err = box.UnwrapKey(malformedBox, bob.Private)
	if err == nil {
		t.Error("UnwrapKey should fail if the content inside the box is not 32 bytes")
	}
}
