package token

import (
	"github.com/golang-jwt/jwt/v5"
)

// Claims defines the standard payload for the entire platform.
type Claims struct {
	jwt.RegisteredClaims
}
