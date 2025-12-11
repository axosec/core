package token

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Manager handles the creation and validation of JWTs.
type JWTManager struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	issuer     string
}

// NewJWTManager initializes the JWT logic.
func NewJWTManager(priv *rsa.PrivateKey, pub *rsa.PublicKey, issuer string) *JWTManager {
	return &JWTManager{
		privateKey: priv,
		publicKey:  pub,
		issuer:     issuer,
	}
}

// Issue generates new JWT token for a user.
//
// Use only within the accounts service
func (m *JWTManager) Issue(userID string, duration time.Duration) (string, error) {
	if m.privateKey == nil {
		return "", ErrMissingPrivateKey
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID.String(),
			Subject:   userID,
			Issuer:    m.issuer,
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	signedToken, err := t.SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

func (m *JWTManager) Validate(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.publicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS512.Name}),
	)

	if err != nil {
		return nil, fmt.Errorf("token parsing failed: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	now := time.Now()

	if claims.IssuedAt.Time.After(now.Add(5 * time.Second)) {
		return nil, fmt.Errorf("token issued in the future (iat: %v)", claims.IssuedAt)
	}

	if claims.NotBefore.Time.After(now.Add(5 * time.Second)) {
		return nil, fmt.Errorf("token is not valid yet (nbf: %v)", claims.NotBefore)
	}

	if claims.ExpiresAt.Time.Before(now.Add(-5 * time.Second)) {
		return nil, fmt.Errorf("token has expired (exp: %v)", claims.ExpiresAt)
	}

	return claims, nil
}
