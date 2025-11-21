package v2

// LoginRequest represents the request body for POST /login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the response for successful login
type LoginResponse struct {
	Status           string                `json:"status"` // "success", "2fa_required", "user_selection_required"
	User             interface{}           `json:"user,omitempty"`
	Users            []interface{}         `json:"users,omitempty"`
	TempToken        string                `json:"temp_token,omitempty"`
	TwoFactorMethods []TwoFactorMethodInfo `json:"two_factor_methods,omitempty"`
	Message          string                `json:"message,omitempty"`
}

// TwoFactorMethodInfo represents a 2FA method option
type TwoFactorMethodInfo struct {
	Type            string   `json:"type"`
	DeliveryOptions []string `json:"delivery_options,omitempty"`
	DisplayName     string   `json:"display_name,omitempty"`
}

// MagicLinkRequest represents the request body for magic link generation
type MagicLinkRequest struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
}

// MagicLinkResponse represents the response for magic link request
type MagicLinkResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// MagicLinkValidateResponse represents the response for magic link validation
type MagicLinkValidateResponse struct {
	Status    string      `json:"status"`
	User      interface{} `json:"user,omitempty"`
	TempToken string      `json:"temp_token,omitempty"`
	Message   string      `json:"message,omitempty"`
}

// PasswordResetInitRequest represents the request to initiate password reset
type PasswordResetInitRequest struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
}

// PasswordResetInitResponse represents the response for password reset initiation
type PasswordResetInitResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// PasswordResetRequest represents the request to complete password reset
type PasswordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// PasswordResetResponse represents the response for password reset completion
type PasswordResetResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// RefreshTokenResponse represents the response for token refresh
type RefreshTokenResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}
