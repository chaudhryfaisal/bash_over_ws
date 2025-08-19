package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// TokenValidator validates authentication tokens
type TokenValidator struct {
	token string
}

// NewTokenValidator creates a new token validator with the given token
func NewTokenValidator(token string) *TokenValidator {
	return &TokenValidator{token: token}
}

// ValidateRequest validates the authentication token from the request
// Supports both query parameter (?token=...) and Authorization header (Bearer ...)
func (tv *TokenValidator) ValidateRequest(r *http.Request) error {
	// Check query parameter first
	if token := r.URL.Query().Get("token"); token != "" {
		if token == tv.token {
			return nil
		}
		return fmt.Errorf("invalid token in query parameter")
	}

	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == tv.token {
				return nil
			}
			return fmt.Errorf("invalid token in authorization header")
		}
		return fmt.Errorf("invalid authorization header format")
	}

	return fmt.Errorf("no authentication token provided")
}

// Middleware creates an HTTP middleware for token validation
func (tv *TokenValidator) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := tv.ValidateRequest(r); err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}