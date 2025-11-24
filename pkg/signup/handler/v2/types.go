package v2

// SignupRequest represents the unified signup request (with or without password)
type SignupRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password,omitempty"`        // Optional - if omitted, passwordless signup
	Username       string `json:"username,omitempty"`
	Fullname       string `json:"fullname,omitempty"`
	InvitationCode string `json:"invitation_code,omitempty"`
	AutoLogin      bool   `json:"auto_login,omitempty"`      // Optional - auto-login after successful signup (requires password)
}

// SignupResponse represents the response for successful signup
type SignupResponse struct {
	UserID  string                 `json:"user_id"`
	Message string                 `json:"message"`
	Status  string                 `json:"status,omitempty"` // "success" when auto-login is enabled
	User    map[string]interface{} `json:"user,omitempty"`   // User data when auto-login is enabled
}
