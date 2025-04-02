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
	"github.com/tendant/simple-idm/pkg/common"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
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
	loginService       *login.LoginService
}

func NewHandle(profileService *profile.ProfileService, twoFaService *twofa.TwoFaService, tokenService tg.TokenService, tokenCookieService tg.TokenCookieService, loginService *login.LoginService, responseHandler ResponseHandler) Handle {
	return Handle{
		profileService:     profileService,
		twoFaService:       twoFaService,
		responseHandler:    responseHandler,
		tokenService:       tokenService,
		tokenCookieService: tokenCookieService,
		loginService:       loginService,
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
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	originalLoginId, err := uuid.Parse(authUser.LoginId)
	if err != nil {
		slog.Error("Failed to parse login ID", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to parse login ID: " + err.Error(),
		}
	}
	originalLogin, err := h.profileService.GetLoginById(r.Context(), originalLoginId)
	if err != nil {
		slog.Error("Failed to get original login", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to get original login: " + err.Error(),
		}
	}
	slog.Info("Current user", "user_uuid", authUser.UserId, "original login", originalLogin)

	data := AssociateLoginJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: ErrInvalidCredentials,
		}
	}

	if data.Username == "" || data.Password == "" {
		slog.Error("Invalid username or password", "username", data.Username, "password length", len(data.Password))
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

	// Check if login is already associated with user
	if login.ID == originalLoginId {
		slog.Warn("login already associated with user", "login_id", login.ID, "user_id", originalLoginId)
		return &Response{
			Code: http.StatusOK,
			body: "Login already associated with user",
		}
	}

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

	// Check if 2FA is enabled for this login
	idmUsers, err := h.profileService.GetUsersByLoginId(r.Context(), login.ID)
	if err != nil {
		slog.Error("Failed to get users by login ID", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to get users by login ID",
		}
	}

	// Prepare login selection required response
	loginOptions := []LoginOption{
		{
			ID:       authUser.LoginId,
			Username: originalLogin.Username,
			Current:  true,
		},
		{
			ID:       login.ID.String(),
			Username: login.Username,
			Current:  false,
		},
	}

	is2FAEnabled, commonMethods, tempToken, err := common.Check2FAEnabled(
		r.Context(),
		w,
		login.ID,
		idmUsers,
		h.twoFaService,
		h.tokenService,
		h.tokenCookieService,
		loginOptions,
	)
	if err != nil {
		slog.Error("Failed to check 2FA", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to check 2FA",
		}
	}

	if is2FAEnabled {
		// Return 2FA required response
		return h.prepare2FARequiredResponse(commonMethods, tempToken)
	}

	return h.prepareLoginSelectionRequiredResponse(loginOptions)
}

// prepare2FARequiredResponse prepares a 2FA required response
func (h Handle) prepare2FARequiredResponse(commonMethods []common.TwoFactorMethod, tempToken *tg.TokenValue) *Response {
	// Convert common.TwoFactorMethod to api.TwoFactorMethodSelection
	var twoFactorMethods []TwoFactorMethodSelection
	err := copier.Copy(&twoFactorMethods, &commonMethods)
	if err != nil {
		slog.Error("Failed to copy 2FA methods", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to process 2FA methods",
		}
	}

	twoFAResp := TwoFactorRequiredResponse{
		Status:           "2fa_required",
		TwoFactorMethods: twoFactorMethods,
		Message:          "Two-factor authentication is required",
	}

	if tempToken != nil {
		twoFAResp.TempToken = tempToken.Token
	}

	return &Response{
		Code:        http.StatusAccepted,
		body:        twoFAResp,
		contentType: "application/json",
	}
}

// prepareLoginSelectionRequiredResponse prepares a login selection required response
func (h Handle) prepareLoginSelectionRequiredResponse(loginOptions []LoginOption) *Response {
	resp := SelectLoginRequiredResponse{
		Status:       "login_selection_required",
		LoginOptions: loginOptions,
		Message:      "Please select which login to use for this account",
	}

	return &Response{
		Code:        http.StatusAccepted,
		body:        resp,
		contentType: "application/json",
	}
}

// CompleteLoginAssociation handles the final step of login association after the user has selected which login to use
func (h Handle) CompleteLoginAssociation(w http.ResponseWriter, r *http.Request) *Response {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Parse request body
	data := CompleteLoginAssociationJSONBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Invalid request body",
		}
	}

	// Validate login ID
	loginID, err := uuid.Parse(data.LoginID)
	if err != nil {
		slog.Error("Invalid login ID format", "login_id", data.LoginID, "error", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Invalid login ID format",
		}
	}

	// Update the user's login ID
	_, err = h.profileService.UpdateLoginId(r.Context(), profile.UpdateLoginIdParam{
		ID:      authUser.UserUuid,
		LoginID: utils.ToNullUUID(loginID),
	})
	if err != nil {
		slog.Error("error updating login ID", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: ErrAssociationFailed,
		}
	}

	slog.Info("login associated successfully",
		"login_id", loginID,
		"user_id", authUser.UserUuid,
	)

	resp := SuccessResponse{
		Result: "Success",
	}
	return CompleteLoginAssociationJSON200Response(resp)
}

// Switch to a different user when multiple users are available for the same login
// (POST /user/switch)
func (h Handle) PostUserSwitch(w http.ResponseWriter, r *http.Request) *Response {
	// Parse request body
	data := PostUserSwitchJSONRequestBody{}
	if err := render.DecodeJSON(r.Body, &data); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

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

	users, err := h.profileService.GetUsersByLoginId(r.Context(), loginId)
	if err != nil {
		slog.Error("Failed to get users by login ID", "err", err)
		return &Response{
			body: "Failed to get users by login ID",
			Code: http.StatusInternalServerError,
		}
	}

	// Check if the requested user is in the list
	var targetUser mapper.User
	found := false
	for _, user := range users {
		if user.UserId == data.UserID {
			targetUser = user
			found = true
			break
		}
	}

	if !found {
		return &Response{
			Code: http.StatusForbidden,
			body: "Not authorized to switch to this user",
		}
	}

	rootModifications, extraClaims := h.profileService.ToTokenClaims(targetUser)

	tokens, err := h.tokenService.GenerateTokens(targetUser.UserId, rootModifications, extraClaims)
	if err != nil {
		slog.Error("Failed to create tokens", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to create tokens",
		}
	}

	err = h.tokenCookieService.SetTokensCookie(w, tokens)
	if err != nil {
		slog.Error("Failed to set tokens in cookies", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to set tokens in cookies",
		}
	}

	// Convert mapped users to API users (including all available users)
	return h.responseHandler.PrepareUserSwitchResponse(users)
}

// Get a list of users associated with the current login
// (GET /users)
func (h Handle) FindUsersWithLogin(w http.ResponseWriter, r *http.Request) *Response {
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

	users, err := h.profileService.GetUsersByLoginId(r.Context(), loginId)
	if err != nil {
		slog.Error("Failed to get users by login ID", "err", err)
		return &Response{
			body: "Failed to get users by login ID",
			Code: http.StatusInternalServerError,
		}
	}

	return h.responseHandler.PrepareUserListResponse(users)
}

// ResponseHandler defines the interface for handling responses during login
type ResponseHandler interface {
	// PrepareUserListResponse prepares a response for a list of users
	PrepareUserListResponse(users []mapper.User) *Response
	// PrepareUserSwitchResponse prepares a response for user switch
	PrepareUserSwitchResponse(users []mapper.User) *Response
}

// DefaultResponseHandler is the default implementation of ResponseHandler
type DefaultResponseHandler struct {
}

// NewDefaultResponseHandler creates a new DefaultResponseHandler
func NewDefaultResponseHandler() ResponseHandler {
	return &DefaultResponseHandler{}
}

// PrepareUserListResponse prepares a response for a list of users
func (h *DefaultResponseHandler) PrepareUserListResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email, _ := user.ExtraClaims["email"].(string)
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		role := ""
		if len(user.Roles) > 0 {
			role = user.Roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  role,
			Email: email,
		})
	}
	return FindUsersWithLoginJSON200Response(apiUsers)
}

// PrepareUserSwitchResponse prepares a response for user switch
func (h *DefaultResponseHandler) PrepareUserSwitchResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email, _ := user.ExtraClaims["email"].(string)
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		role := ""
		if len(user.Roles) > 0 {
			role = user.Roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  role,
			Email: email,
		})
	}

	response := Login{
		Status:  "success",
		Message: "Successfully switched user",
		Users:   apiUsers,
	}

	return PostUserSwitchJSON200Response(response)
}
