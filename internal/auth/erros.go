package auth

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidToken = errors.New("invalid credentials")
var ErrEmailNotVerified = errors.New("email not verified")
var ErrRefreshReuse = errors.New("Attempted to reuse token")
