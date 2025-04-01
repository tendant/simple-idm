package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/profile"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
	"github.com/tendant/simple-idm/pkg/twofa"
	"github.com/tendant/simple-idm/pkg/utils"
	"golang.org/x/exp/slog"
)

type Handle struct {
	profileService     *profile.ProfileService
	twoFaService       *twofa.TwoFaService
	responseHandler    ResponseHandler
	tokenService       tg.TokenService
	tokenCookieService tg.TokenCookieService
  loginService   *login.LoginService
}

func NewHandle(profileService *profile.ProfileService, twoFaService *twofa.TwoFaService, tokenService tg.TokenService, tokenCookieService tg.TokenCookieService, loginService *login.LoginService) Handle {
	return Handle{
		profileService:     profileService,
		twoFaService:       twoFaService,
		responseHandler:    NewDefaultResponseHandler(),
		tokenService:       tokenService,
		tokenCookieService: tokenCookieService,
    loginService:   loginService,
	}
}

const (
	ErrInvalidCredentials = "invalid username or password"
	ErrAssociationFailed  = "failed to associate login with current user"
)

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

	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

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
	err := h.profileService.UpdatePassword(r.Context(), profile.UpdatePasswordParams{
		LoginID:         authUser.LoginID,
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

// Get login 2FA methods
// (GET /2fa)
func (h Handle) Get2faMethods(w http.ResponseWriter, r *http.Request) *Response {
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
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

	res, err := h.twoFaService.FindTwoFAsByLoginId(r.Context(), loginId)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": err.Error()},
		}
	}

	var (
		methods []TwoFactorMethod
		resp    TwoFactorMethods
	)

	for _, v := range res {
		methods = append(methods, TwoFactorMethod{
			TwoFactorID: v.TwoFactorId.String(),
			Type:        v.TwoFactorType,
			Enabled:     v.TwoFactorEnabled,
		})
	}

	resp.Count = len(methods)
	resp.Methods = methods

	return Get2faMethodsJSON200Response(resp)
}

// Disable an existing 2FA method
// (POST /2fa/disable)
func (h Handle) Post2faDisable(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
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

	data := Post2faEnableJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	err = h.twoFaService.DisableTwoFactor(r.Context(), loginId, string(data.TwofaType))
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Error(),
		}
	}

	return Post2faDisableJSON200Response(resp)
}

// Enable an existing 2FA method
// (POST /2fa/enable)
func (h Handle) Post2faEnable(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
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

	data := Post2faEnableJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// Find enabled 2FA methods
	err = h.twoFaService.EnableTwoFactor(r.Context(), loginId, string(data.TwofaType))
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Error(),
		}
	}

	return Post2faEnableJSON200Response(resp)
}

// Create a new 2FA method
// (POST /2fa/setup)
func (h Handle) Post2faSetup(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
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

// Delete a 2FA method
// (POST /2fa/delete)
func (h Handle) Delete2fa(w http.ResponseWriter, r *http.Request) *Response {
	//TODO: add check: can the user directly delete 2FA
	var resp SuccessResponse
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
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

	data := Delete2faJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	twofaId, err := uuid.Parse(*data.TwofaID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid 2fa id",
		}
	}

	err = h.twoFaService.DeleteTwoFactor(r.Context(), twofa.DeleteTwoFactorParams{
		LoginId:       loginId,
		TwoFactorId:   twofaId,
		TwoFactorType: string(data.TwofaType),
	})
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Error(),
		}
	}

	return Delete2faJSON200Response(resp)
}

// Associate a login
// (POST /login/associate)
func (h Handle) AssociateLogin(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}
	data := AssociateLoginJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: ErrInvalidCredentials,
		}
	}

	if data.Username == "" || data.Password == "" {
		return &Response{
			Code: http.StatusBadRequest,
			body: ErrInvalidCredentials,
		}
	}

	// Find login by username
	login, err := h.loginService.FindLoginByUsername(r.Context(), data.Username)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Error("no login found with username: %s", data.Username)
			return &Response{
				Code: http.StatusBadRequest,
				body: ErrInvalidCredentials,
			}
		}
		slog.Error("error finding login with username: %s", data.Username)
		return &Response{
			Code: http.StatusInternalServerError,
			body: ErrInvalidCredentials,
		}
	}

	slog.Info("found login with username: %s", data.Username, "login", login.ID)

	// Hash the password for logging purposes only
	hashedForLogging := fmt.Sprintf("%x", sha256.Sum256([]byte(data.Password)))
	slog.Info("password hash for logging", "password_hash", hashedForLogging)

	// Verify password
	slog.Info("hashed password", "hashed_password", string(login.Password))
	valid, err := h.loginService.CheckPasswordByLoginId(r.Context(), login.ID, data.Password, string(login.Password))
	if err != nil || !valid {
		slog.Error("error checking password: %w", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: ErrInvalidCredentials,
		}
	}

	slog.Info("password verified successfully", "login", login.ID)

	_, err = h.profileService.UpdateLoginId(r.Context(), profile.UpdateLoginIdParam{
		ID:      authUser.UserUuid,
		LoginID: utils.ToNullUUID(login.ID),
	})
	if err != nil {
		slog.Error("error updating login ID", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: ErrAssociationFailed,
		}
	}

	slog.Info("login associated successfully",
		"login_id", login.ID,
		"user_id", authUser.UserUuid,
		"username", data.Username,
	)

	resp.Result = "success"

	return AssociateLoginJSON200Response(resp)

}

