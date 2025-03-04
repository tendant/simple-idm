package logins

import (
	"time"

	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
)

// LoginModel represents a login in the service layer
type LoginModel struct {
	ID               string     `json:"id"`
	Username         string     `json:"username"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
	CreatedBy        string     `json:"created_by,omitempty"`
	TwoFactorEnabled bool       `json:"two_factor_enabled"`
	PasswordVersion  int        `json:"password_version,omitempty"`
}

// LoginListResponse represents the response for listing logins
type LoginListResponse struct {
	Logins []LoginModel `json:"logins"`
	Total  int64        `json:"total"`
}

// LoginCreateRequest represents the request to create a new login
type LoginCreateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginUpdateRequest represents the request to update a login
type LoginUpdateRequest struct {
	Username         *string `json:"username,omitempty"`
	TwoFactorEnabled *bool   `json:"two_factor_enabled,omitempty"`
}

// PasswordUpdateRequest represents the request to update a password
type PasswordUpdateRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// TwoFactorResponse represents the response when enabling two-factor authentication
type TwoFactorResponse struct {
	Secret string `json:"secret"`
	QRCode string `json:"qr_code"`
}

// BackupCodesResponse represents the response when generating backup codes
type BackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

// FromDBLogin converts a database login to a service login model
func FromDBLogin(dbLogin *loginsdb.Login) LoginModel {
	login := LoginModel{
		ID:        dbLogin.ID.String(),
		CreatedAt: dbLogin.CreatedAt,
		UpdatedAt: dbLogin.UpdatedAt,
	}

	if dbLogin.Username.Valid {
		login.Username = dbLogin.Username.String
	}

	if dbLogin.CreatedBy.Valid {
		login.CreatedBy = dbLogin.CreatedBy.String
	}

	if dbLogin.DeletedAt.Valid {
		deletedAt := dbLogin.DeletedAt.Time
		login.DeletedAt = &deletedAt
	}

	if dbLogin.TwoFactorEnabled.Valid {
		login.TwoFactorEnabled = dbLogin.TwoFactorEnabled.Bool
	}

	if dbLogin.PasswordVersion.Valid {
		login.PasswordVersion = int(dbLogin.PasswordVersion.Int32)
	}

	return login
}

// FromDBLogins converts a slice of database logins to service login models
func FromDBLogins(dbLogins []loginsdb.Login) []LoginModel {
	logins := make([]LoginModel, len(dbLogins))
	for i, dbLogin := range dbLogins {
		logins[i] = FromDBLogin(&dbLogin)
	}
	return logins
}
