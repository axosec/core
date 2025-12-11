package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/axosec/core/crypto/token"
	"github.com/golang-jwt/jwt/v5"
)

// generateTestKeys creates a fresh 2048-bit RSA key pair for testing.
func generateTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	// Generate key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}
	return priv, &priv.PublicKey
}

func TestJWT_HappyPath(t *testing.T) {
	priv, pub := generateTestKeys(t)
	authService := token.NewJWTManager(priv, pub, "test-cloud")

	chatService := token.NewJWTManager(nil, pub, "test-cloud")

	// Issue a token
	userID := "user-123"
	duration := time.Minute

	tokenStr, err := authService.Issue(userID, duration)
	if err != nil {
		t.Fatalf("Failed to issue token: %v", err)
	}

	// Validate the token
	claims, err := chatService.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	//  Assertions
	if claims.Subject != userID {
		t.Errorf("Expected UserID %s, got %s", userID, claims.Subject)
	}
	if claims.Issuer != "test-cloud" {
		t.Errorf("Expected Issuer test-cloud, got %s", claims.Issuer)
	}
	if len(claims.ID) < 10 {
		t.Error("Token ID (JTI) appears too short or missing")
	}
}

func TestJWT_TimeChecks(t *testing.T) {
	priv, pub := generateTestKeys(t)
	manager := token.NewJWTManager(priv, pub, "test-cloud")

	tests := []struct {
		name         string
		modifyClaims func(c *token.Claims)
		expectError  bool
		errorMsg     string
	}{
		{
			name: "Expired Token (exp)",
			modifyClaims: func(c *token.Claims) {
				// Expired 1 hour ago
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
			},
			expectError: true,
			errorMsg:    "token has expired",
		},
		{
			name: "Future Token (iat) - Time Travel",
			modifyClaims: func(c *token.Claims) {
				// Issued 1 hour in the future
				c.IssuedAt = jwt.NewNumericDate(time.Now().Add(1 * time.Hour))
				c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Hour))
				c.NotBefore = jwt.NewNumericDate(time.Now())
			},
			expectError: true,
			errorMsg:    "token issued in the future",
		},
		{
			name: "Premature Use (nbf)",
			modifyClaims: func(c *token.Claims) {
				// Valid in 10 minutes
				c.IssuedAt = jwt.NewNumericDate(time.Now())
				c.NotBefore = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
			},
			expectError: true,
			errorMsg:    "token is not valid yet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create base claims
			claims := token.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "test-user",
					Issuer:    "test-cloud",
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}

			tt.modifyClaims(&claims)

			rawToken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
			signedStr, err := rawToken.SignedString(priv)
			if err != nil {
				t.Fatalf("Failed to sign token: %v", err)
			}

			_, err = manager.Validate(signedStr)

			// Check results
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else {
					if !strings.Contains(err.Error(), tt.errorMsg) && !strings.Contains(err.Error(), "token is expired") {
						t.Errorf("Expected error message to contain '%s', got '%v'", tt.errorMsg, err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected success, got error: %v", err)
				}
			}
		})
	}
}

func TestSecurity_TamperedToken(t *testing.T) {
	priv, pub := generateTestKeys(t)
	manager := token.NewJWTManager(priv, pub, "test-cloud")

	validToken, _ := manager.Issue("user-1", time.Hour)

	parts := strings.Split(validToken, ".")
	tamperedPayload := parts[1] + "junk"
	tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]

	_, err := manager.Validate(tamperedToken)
	if err == nil {
		t.Fatal("SECURITY FAIL: Validator accepted tampered token")
	}
}

func TestSecurity_AlgorithmDowngrade(t *testing.T) {
	priv, pub := generateTestKeys(t)
	manager := token.NewJWTManager(priv, pub, "test-cloud")

	claims := token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Issuer:    "test-cloud",
		},
	}

	weakToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	weakString, _ := weakToken.SignedString(priv)

	_, err := manager.Validate(weakString)

	if err == nil {
		t.Fatal("SECURITY FAIL: Validator accepted RS256 when configured for RS512 only!")
	}

	if !strings.Contains(err.Error(), "unexpected signing method") && !strings.Contains(err.Error(), "signing method RS256 is invalid") {
		t.Logf("Got expected error but message was generic: %v", err)
	}
}

func TestSecurity_NoneAlgorithm(t *testing.T) {
	priv, pub := generateTestKeys(t)
	manager := token.NewJWTManager(priv, pub, "test-cloud")

	// Header: {"alg":"none","typ":"JWT"}
	header := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	// Payload: {"sub":"hacker"}
	payload := "eyJzdWIiOiJoYWNrZXIifQ"

	fakeToken := header + "." + payload + "."

	_, err := manager.Validate(fakeToken)
	if err == nil {
		t.Fatal("SECURITY FAIL: Validator accepted 'none' algorithm token!")
	}
}

func TestSecurity_WrongKeyAttack(t *testing.T) {
	_, truePub := generateTestKeys(t)

	attackerPriv, _ := generateTestKeys(t)

	attackerManager := token.NewJWTManager(attackerPriv, nil, "test-cloud")
	fakeToken, _ := attackerManager.Issue("hacker", time.Hour)

	victimManager := token.NewJWTManager(nil, truePub, "test-cloud")
	_, err := victimManager.Validate(fakeToken)

	if err == nil {
		t.Fatal("SECURITY FAIL: Validated token signed by wrong private key!")
	}
}

