package iam

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID             uuid.UUID  `json:"id"`
	CreatedAt      time.Time  `json:"created_at"`
	LastModifiedAt time.Time  `json:"last_modified_at"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
	CreatedBy      string     `json:"created_by,omitempty"`
	Email          string     `json:"email"`
	Name           string     `json:"name,omitempty"`
	LoginID        *uuid.UUID `json:"login_id,omitempty"`
	Username       string     `json:"username,omitempty"`
}

// Role represents a role in the system
type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
}

// UserWithRoles represents a user with their assigned roles
type UserWithRoles struct {
	User
	Roles []Role `json:"roles"`
}

// CreateUserParams contains parameters for creating a new user
type CreateUserParams struct {
	Email   string     `json:"email"`
	Name    string     `json:"name,omitempty"`
	LoginID *uuid.UUID `json:"login_id,omitempty"`
}

// UpdateUserParams contains parameters for updating a user
type UpdateUserParams struct {
	ID      uuid.UUID  `json:"id"`
	Email   string     `json:"email"`
	Name    string     `json:"name,omitempty"`
	LoginID *uuid.UUID `json:"login_id,omitempty"`
}

// UserRoleParams contains parameters for assigning a role to a user
type UserRoleParams struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}
