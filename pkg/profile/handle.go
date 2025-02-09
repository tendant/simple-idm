package profile

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/exp/slog"
)

type Handle struct {
	profileService *ProfileService
}

func NewHandle(profileService *ProfileService) Handle {
	return Handle{
		profileService: profileService,
	}
}

// PutPassword handles password change requests
// (PUT /password)
func (h Handle) PutPassword(w http.ResponseWriter, r *http.Request) *Response {
	// Get user UUID from context (assuming it's set by auth middleware)
	userUUID, ok := r.Context().Value("user_uuid").(string)
	if !ok {
		slog.Error("User UUID not found in context")
		return &Response{
			Code: http.StatusUnauthorized,
			body: map[string]string{
				"code":    "unauthorized",
				"message": "User not authenticated",
			},
		}
	}

	// Parse UUID
	parsedUUID, err := uuid.Parse(userUUID)
	if err != nil {
		slog.Error("Invalid UUID format", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{
				"code":    "invalid_uuid",
				"message": "Invalid user ID format",
			},
		}
	}

	// Parse request body
	var data PutPasswordJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		slog.Error("Failed to decode request body", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{
				"code":    "invalid_request",
				"message": "Invalid request body",
			},
		}
	}

	// Validate request
	if data.CurrentPassword == "" || data.NewPassword == "" {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{
				"code":    "invalid_request",
				"message": "Current password and new password are required",
			},
		}
	}

	// Update password
	err = h.profileService.UpdatePassword(r.Context(), UpdatePasswordParams{
		UserUUID:        parsedUUID,
		CurrentPassword: data.CurrentPassword,
		NewPassword:     data.NewPassword,
	})

	if err != nil {
		if err.Error() == "invalid current password" {
			return &Response{
				Code: http.StatusForbidden,
				body: map[string]string{
					"code":    "invalid_password",
					"message": "Current password is incorrect",
				},
			}
		}
		slog.Error("Failed to update password", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{
				"code":    "internal_error",
				"message": "Failed to update password",
			},
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{
			"message": "Password updated successfully",
		},
	}
}
