package profile

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/profile/profiledb"
	"golang.org/x/exp/slog"
)

type ProfileService struct {
	queries *profiledb.Queries
}

func NewProfileService(queries *profiledb.Queries) *ProfileService {
	return &ProfileService{
		queries: queries,
	}
}

type UpdatePasswordParams struct {
	UserUUID        uuid.UUID
	CurrentPassword string
	NewPassword     string
}

// UpdatePassword updates a user's password after verifying their current password
func (s *ProfileService) UpdatePassword(ctx context.Context, params UpdatePasswordParams) error {
	// Get the user to verify they exist
	user, err := s.queries.GetUserByUUID(ctx, params.UserUUID)
	if err != nil {
		slog.Error("Failed to find user", "uuid", params.UserUUID, "err", err)
		return fmt.Errorf("user not found")
	}

	// Verify the current password
	match, err := login.CheckPasswordHash(params.CurrentPassword, string(user.Password))
	if err != nil || !match {
		slog.Error("Invalid current password", "uuid", params.UserUUID)
		return fmt.Errorf("invalid current password")
	}

	// Hash the new password
	hashedPassword, err := login.HashPassword(params.NewPassword)
	if err != nil {
		slog.Error("Failed to hash new password", "err", err)
		return fmt.Errorf("failed to process new password")
	}

	// Update the password in the database
	err = s.queries.UpdateUserPassword(ctx, profiledb.UpdateUserPasswordParams{
		Uuid:     params.UserUUID,
		Password: []byte(hashedPassword),
	})
	if err != nil {
		slog.Error("Failed to update password", "uuid", params.UserUUID, "err", err)
		return fmt.Errorf("failed to update password")
	}

	return nil
}
