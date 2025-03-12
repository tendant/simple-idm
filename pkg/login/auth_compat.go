package login

import (
	"github.com/tendant/simple-idm/pkg/login/auth"
)

// Re-export types from auth package for backward compatibility
type AuthUser = auth.AuthUser
type ExtraClaims = auth.ExtraClaims

// Re-export constants and variables from auth package for backward compatibility
var (
	AuthUserKey = auth.AuthUserKey
)

// Re-export functions from auth package for backward compatibility
var (
	AuthUserMiddleware = auth.AuthUserMiddleware
	Verifier = auth.Verifier
	TokenFromCookie = auth.TokenFromCookie
)
