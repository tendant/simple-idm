package externalprovider

import (
	"fmt"
	"net/url"
	"strings"
)

// // ExternalProvider represents an external OAuth2/OIDC identity provider configuration
type ExternalProvider struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	DisplayName  string   `json:"display_name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url"`
	Scopes       []string `json:"scopes"`
	Enabled      bool     `json:"enabled"`
	IconURL      string   `json:"icon_url,omitempty"`
	Description  string   `json:"description,omitempty"`
}

// // OAuth2State represents the state parameter used in OAuth2 flows for security
type OAuth2State struct {
	State       string `json:"state"`
	Provider    string `json:"provider"`
	RedirectURL string `json:"redirect_url,omitempty"`
	ExpiresAt   int64  `json:"expires_at"`
}

// // ExternalUserInfo represents normalized user information from external providers
type ExternalUserInfo struct {
	ProviderID    string `json:"provider_id"`
	ExternalID    string `json:"external_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

// // TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// ValidateConfig validates the provider configuration
func (p *ExternalProvider) ValidateConfig() error {
	if p.ID == "" {
		return fmt.Errorf("provider ID is required")
	}
	if p.Name == "" {
		return fmt.Errorf("provider name is required")
	}
	if p.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if p.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}
	if p.AuthURL == "" {
		return fmt.Errorf("authorization URL is required")
	}
	if p.TokenURL == "" {
		return fmt.Errorf("token URL is required")
	}
	if p.UserInfoURL == "" {
		return fmt.Errorf("user info URL is required")
	}

	// Validate URLs
	if _, err := url.Parse(p.AuthURL); err != nil {
		return fmt.Errorf("invalid authorization URL: %w", err)
	}
	if _, err := url.Parse(p.TokenURL); err != nil {
		return fmt.Errorf("invalid token URL: %w", err)
	}
	if _, err := url.Parse(p.UserInfoURL); err != nil {
		return fmt.Errorf("invalid user info URL: %w", err)
	}

	return nil
}

// // BuildAuthURL builds the OAuth2 authorization URL with the given parameters
func (p *ExternalProvider) BuildAuthURL(state, redirectURI string) (string, error) {
	authURL, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth URL: %w", err)
	}

	params := url.Values{}
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)

	if len(p.Scopes) > 0 {
		params.Set("scope", strings.Join(p.Scopes, " "))
	}

	authURL.RawQuery = params.Encode()
	return authURL.String(), nil
}

// GetDefaultScopes returns the default scopes for the provider
func (p *ExternalProvider) GetDefaultScopes() []string {
	if len(p.Scopes) > 0 {
		return p.Scopes
	}
	// Default scopes for most providers
	return []string{"openid", "profile", "email"}
}
