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

// ToMappedUser converts a User struct to a MappedUser struct
func (u User) ToMappedUser() MappedUser {
	// Extract role from user's ExtraClaims
	role := ""
	if roleVal, ok := u.ExtraClaims["role"]; ok {
		if roleStr, ok := roleVal.(string); ok {
			role = roleStr
		}
	}
	
	// Extract tenant and department information from ExtraClaims
	var tenantUuid uuid.UUID
	var deptUuid uuid.UUID
	tenantName := ""
	deptName := ""
	
	if tenantUuidVal, ok := u.ExtraClaims["tenant_uuid"]; ok {
		if tenantUuidStr, ok := tenantUuidVal.(string); ok {
			parsedUuid, err := uuid.Parse(tenantUuidStr)
			if err == nil {
				tenantUuid = parsedUuid
			}
		}
	}
	
	if deptUuidVal, ok := u.ExtraClaims["dept_uuid"]; ok {
		if deptUuidStr, ok := deptUuidVal.(string); ok {
			parsedUuid, err := uuid.Parse(deptUuidStr)
			if err == nil {
				deptUuid = parsedUuid
			}
		}
	}
	
	if tenantNameVal, ok := u.ExtraClaims["tenant_name"]; ok {
		if tnStr, ok := tenantNameVal.(string); ok {
			tenantName = tnStr
		}
	}
	
	if deptNameVal, ok := u.ExtraClaims["dept_name"]; ok {
		if dnStr, ok := deptNameVal.(string); ok {
			deptName = dnStr
		}
	}
	
	return MappedUser{
		UserId:      u.UserID,
		LoginID:     u.LoginID,
		Email:       u.UserInfo.Email,
		DisplayName: u.DisplayName,
		ExtraClaims: u.ExtraClaims,
		TenantUuid:  tenantUuid,
		DeptUuid:    deptUuid,
		TenantName:  tenantName,
		DeptName:    deptName,
		Role:        role,
	}
}

// ToMappedUsers converts a slice of User structs to a slice of MappedUser structs
func ToMappedUsers(users []User) []MappedUser {
	mappedUsers := make([]MappedUser, 0, len(users))
	for _, user := range users {
		mappedUsers = append(mappedUsers, user.ToMappedUser())
	}
	return mappedUsers
}

// FromMappedUser converts a MappedUser struct to a User struct
func FromMappedUser(mu MappedUser) User {
	// Create UserInfo from MappedUser fields
	userInfo := UserInfo{
		Email: mu.Email,
	}
	
	// Create a new User
	user := User{
		UserID:      mu.UserId,
		LoginID:     mu.LoginID,
		DisplayName: mu.DisplayName,
		UserInfo:    userInfo,
		ExtraClaims: mu.ExtraClaims,
	}
	
	// Add additional fields to ExtraClaims if they're not empty
	if mu.Role != "" {
		user.ExtraClaims["role"] = mu.Role
	}
	
	// Add tenant and department info to ExtraClaims
	if mu.TenantUuid != uuid.Nil {
		user.ExtraClaims["tenant_uuid"] = mu.TenantUuid.String()
	}
	
	if mu.DeptUuid != uuid.Nil {
		user.ExtraClaims["dept_uuid"] = mu.DeptUuid.String()
	}
	
	if mu.TenantName != "" {
		user.ExtraClaims["tenant_name"] = mu.TenantName
	}
	
	if mu.DeptName != "" {
		user.ExtraClaims["dept_name"] = mu.DeptName
	}
	
	return user
}

// FromMappedUsers converts a slice of MappedUser structs to a slice of User structs
func FromMappedUsers(mappedUsers []MappedUser) []User {
	users := make([]User, 0, len(mappedUsers))
	for _, mu := range mappedUsers {
		users = append(users, FromMappedUser(mu))
	}
	return users
}
