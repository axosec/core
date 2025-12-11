package token

import "errors"

var (
	ErrMissingPrivateKey = errors.New("cannot issue token: private key is missing")
	ErrInvalidClaims     = errors.New("invalid token claims")
)
