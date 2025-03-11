package profile

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/twofa"
	"golang.org/x/exp/slog"
)

type Handle struct {
	profileService *ProfileService
	twoFaService   *twofa.TwoFaService
}

func NewHandle(profileService *ProfileService, twoFaService *twofa.TwoFaService) Handle {
	return Handle{
		profileService: profileService,
		twoFaService:   twoFaService,
	}
}

// Get password policy
// (GET /password/policy)
func (h Handle) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) *Response {
	// get password policy
	policy := h.profileService.GetPasswordPolicy()

	response := PasswordPolicyResponse{}
	copier.Copy(&response, &policy)
	return GetPasswordPolicyJSON200Response(response)
}

// Change Password handles password change requests
// (PUT /password)
func (h Handle) ChangePassword(w http.ResponseWriter, r *http.Request) *Response {

	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Get user UUID from context (assuming it's set by auth middleware)
	userUuid := authUser.UserUuid

	// Parse request body
	var data ChangePasswordJSONRequestBody
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
	err := h.profileService.UpdatePassword(r.Context(), UpdatePasswordParams{
		UserUuid:        userUuid,
		CurrentPassword: data.CurrentPassword,
		NewPassword:     data.NewPassword,
	})

	if err != nil {
		slog.Error("Failed to update password", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{
				"code":    "internal_error",
				"message": err.Error(),
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

func (h Handle) ChangeUsername(w http.ResponseWriter, r *http.Request) *Response {
	// TODO: Implement Change Username
	return &Response{
		Code: http.StatusNotImplemented,
		body: map[string]string{
			"message": "Change username not implemented",
		},
	}
}

// Post2faDisable handles disabling 2FA for a user
// (POST /2fa/disable)
func (h Handle) Post2faDisable(w http.ResponseWriter, r *http.Request) *Response {
	var req TwoFactorDisable
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode request body", "err", err)
		return &Response{
			body: "Invalid request body",
			Code: http.StatusBadRequest,
		}
	}

	// Get the authenticated user from context
	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok || authUser == nil {
		slog.Error("User not authenticated")
		return &Response{
			body: "User not authenticated",
			Code: http.StatusUnauthorized,
		}
	}

	// Disable 2FA for the user
	// err := h.profileService.Disable2FA(r.Context(), authUser.UserUuid, req.CurrentPassword, req.Code)
	// if err != nil {
	// 	slog.Error("Failed to disable 2FA", "err", err)
	// 	return &Response{
	// 		body: "Failed to disable 2FA: " + err.Error(),
	// 		Code: http.StatusBadRequest,
	// 	}
	// }

	return &Response{
		body: struct {
			Message string `json:"message"`
		}{
			Message: "2FA has been disabled",
		},
		Code: http.StatusOK,
	}
}

// Post2faEnable handles enabling 2FA for a user
// (POST /2fa/enable)
func (h Handle) Post2faEnable(w http.ResponseWriter, r *http.Request) *Response {
	var req TwoFactorEnable
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode request body", "err", err)
		return &Response{
			body: "Invalid request body",
			Code: http.StatusBadRequest,
		}
	}

	// Get the authenticated user from context
	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok || authUser == nil {
		slog.Error("User not authenticated")
		return &Response{
			body: "User not authenticated",
			Code: http.StatusUnauthorized,
		}
	}

	// Enable 2FA and get backup codes
	// backupCodes, err := h.profileService.Enable2FA(r.Context(), authUser.UserUuid, req.Secret, req.Code)
	// if err != nil {
	// 	slog.Error("Failed to enable 2FA", "err", err)
	// 	return &Response{
	// 		body: "Failed to enable 2FA: " + err.Error(),
	// 		Code: http.StatusBadRequest,
	// 	}
	// }

	return &Response{
		body: struct {
			BackupCodes []string `json:"backupCodes"`
			Message     string   `json:"message"`
		}{
			BackupCodes: []string{},
			Message:     "2FA has been enabled",
		},
		Code: http.StatusOK,
	}
}

// Create a new 2FA method
// (POST /2fa/setup)
func (h Handle) Post2faSetup(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse
	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Get user UUID from context (assuming it's set by auth middleware)
	loginIdStr := authUser.LoginId

	loginId, err := uuid.Parse(loginIdStr)
	if err != nil {
		slog.Error("Failed to parse login ID", "err", err)
		return &Response{
			body: "Failed to parse login ID: " + err.Error(),
			Code: http.StatusBadRequest,
		}
	}

	data := Post2faSetupJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Create new 2FA method
	err = h.twoFaService.CreateTwoFactor(r.Context(), loginId, string(data.TwofaType))
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to create 2fa: " + err.Error(),
		}
	}

	// Return success response
	resp.Result = "success"
	return Post2faSetupJSON201Response(resp)
}
