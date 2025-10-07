package api

// VerifyEmailRequest represents the request to verify an email
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmailResponse represents the response after email verification
type VerifyEmailResponse struct {
	Message    string `json:"message"`
	VerifiedAt string `json:"verified_at"`
}

// ResendVerificationRequest represents the request to resend verification email
type ResendVerificationRequest struct {
	UserId *string `json:"user_id,omitempty"`
}

// ResendVerificationResponse represents the response after resending verification
type ResendVerificationResponse struct {
	Message string `json:"message"`
}

// VerificationStatusResponse represents the verification status
type VerificationStatusResponse struct {
	EmailVerified bool    `json:"email_verified"`
	VerifiedAt    *string `json:"verified_at,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}
