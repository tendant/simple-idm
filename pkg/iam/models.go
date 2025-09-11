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

// Group represents a group in the system
type Group struct {
	ID          uuid.UUID  `json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
}

// UserWithGroups represents a user with their assigned groups
type UserWithGroups struct {
	User
	Groups []Group `json:"groups"`
}

// UserWithRolesAndGroups represents a user with their assigned roles and groups
type UserWithRolesAndGroups struct {
	User
	Roles  []Role  `json:"roles"`
	Groups []Group `json:"groups"`
}

// CreateGroupParams contains parameters for creating a new group
type CreateGroupParams struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UpdateGroupParams contains parameters for updating a group
type UpdateGroupParams struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
}

// UserGroupParams contains parameters for assigning a group to a user
type UserGroupParams struct {
	UserID  uuid.UUID `json:"user_id"`
	GroupID uuid.UUID `json:"group_id"`
}
