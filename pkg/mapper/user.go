package mapper

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserInfo represents standard OIDC claims for a user
type UserInfo struct {
	Sub               string    `json:"sub,omitempty"`            // Subject - Identifier for the End-User (required)
	Name              string    `json:"name,omitempty"`           // End-User's full name
	PreferredName     string    `json:"preferred_name,omitempty"` // Name by which the End-User wishes to be referred to
	PreferredUsername string    `json:"preferred_username,omitempty"`
	Email             string    `json:"email,omitempty"`          // End-User's preferred e-mail address
	EmailVerified     bool      `json:"email_verified,omitempty"` // True if email has been verified
	UpdatedAt         time.Time `json:"updated_at,omitempty"`     // Time the information was last updated
	PhoneNumber       string    `json:"phone_number,omitempty"`   // End-User's preferred telephone number
	Birthdate         string    `json:"birthdate,omitempty"`      // End-User's birthday
}

// User struct aligned with OpenID Connect (OIDC) standard claims
// while maintaining backward compatibility with existing fields
type User struct {
	// Backward compatibility fields
	UserID      string `json:"user_id,omitempty"`      // Legacy user ID (maps to sub)
	LoginID     string `json:"login_id,omitempty"`     // Legacy login ID
	DisplayName string `json:"display_name,omitempty"` // Legacy display name (maps to preferred_name)

	// Embedded types containing standard and additional claims
	UserInfo    UserInfo               // Standard OIDC claims
	ExtraClaims map[string]interface{} // Organization-specific and additional claims (interface type)

}

type UserRepository interface {
	FindUsersByLoginID(ctx context.Context, loginID uuid.UUID) ([]User, error)
	GetUserByUserID(ctx context.Context, userID uuid.UUID) (User, error)
	FindUsernamesByEmail(ctx context.Context, email string) ([]string, error)
}
