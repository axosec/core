package token


import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func LoadKeysFromFiles(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKeyBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key file: %w\n", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w\n", err)
	}

	publicKeyBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key file: %w\n", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w\n", err)
	}

	return privateKey, publicKey, nil
}
