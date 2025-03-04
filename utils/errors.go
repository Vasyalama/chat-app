package utils

import "errors"

// Custom error definitions
var (
	ErrUserNotFound        = errors.New("user not found")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenInvalid        = errors.New("invalid token")
	ErrUnauthorized        = errors.New("unauthorized access")
	ErrSessionNotFound     = errors.New("session not found")
	ErrInternalServer      = errors.New("internal server error")
	ErrInvalidRequest      = errors.New("invalid request data")
	ErrNoEmailVerification = errors.New("no email verification")
	ErrInvalidCode         = errors.New("invalid code")
	ErrNoRefreshCookie     = errors.New("no cookie refresh provided")
	ErrEmailAlreadyExists  = errors.New("email already exists")
)
