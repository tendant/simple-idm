package logins

import "fmt"

// ErrUsernameAlreadyExists is returned when attempting to create a login with a username that already exists
type ErrUsernameAlreadyExists struct {
	Username string
}

func (e ErrUsernameAlreadyExists) Error() string {
	return fmt.Sprintf("username already exists: %s", e.Username)
}

// ErrPasswordComplexity is returned when a password does not meet complexity requirements
type ErrPasswordComplexity struct {
	Details string
}

func (e ErrPasswordComplexity) Error() string {
	return fmt.Sprintf("password does not meet complexity requirements: %s", e.Details)
}
