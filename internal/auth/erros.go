package auth

import (
	"errors"
	"net/http"
)

var (
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrInvalidToken             = errors.New("invalid token")
	ErrEmptyUsername            = errors.New("username is required")
	ErrInvalidEmail             = errors.New("email format is invalid")
	ErrEmailNotVerified         = errors.New("email not verified")
	ErrRefreshReuse             = errors.New("attempted to reuse token")
	ErrEmailAlreadyExists       = errors.New("email already exists")
	ErrInvalidVerificationToken = errors.New("invalid or expired verification token")
	ErrShortPassword            = errors.New("password must be greater than 3 characters")
)

func mapAuthError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrEmailAlreadyExists):
		return http.StatusConflict, "email already exists"
	case errors.Is(err, ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid credentials"
	case errors.Is(err, ErrInvalidToken):
		return http.StatusUnauthorized, "invalid token"
	case errors.Is(err, ErrEmailNotVerified):
		return http.StatusForbidden, "email not verified"
	case errors.Is(err, ErrRefreshReuse):
		return http.StatusUnauthorized, "refresh token reuse detected"
	case errors.Is(err, ErrInvalidVerificationToken):
		return http.StatusBadRequest, "invalid or expired verification token"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

func respondJSONError(w http.ResponseWriter, err error) {
	status, message := mapAuthError(err)
	writeJSON(w, status, ErrorResponse{Error: message})
}

func respondTextError(w http.ResponseWriter, err error) {
	status, message := mapAuthError(err)
	http.Error(w, message, status)
}
