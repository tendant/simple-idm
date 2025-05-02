package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/common"
	"github.com/tendant/simple-idm/pkg/device"
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
	deviceService      *device.DeviceService
}

func NewHandle(profileService *profile.ProfileService, twoFaService *twofa.TwoFaService, tokenService tg.TokenService, tokenCookieService tg.TokenCookieService, loginService *login.LoginService, deviceService *device.DeviceService, responseHandler ResponseHandler) Handle {
	return Handle{
		profileService:     profileService,
		twoFaService:       twoFaService,
		responseHandler:    responseHandler,
		tokenService:       tokenService,
		tokenCookieService: tokenCookieService,
		loginService:       loginService,
		deviceService:      deviceService,
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
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Parse request body
	var data ChangeUsernameJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		slog.Error("Failed to decode request body", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{
				"code":    "invalid_request",
				"message": "Invalid new username",
			},
		}
	}

	if data.NewUsername == "" {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{
				"code":    "invalid_request",
				"message": "Invalid new username",
			},
		}
	}

	loginId, err := uuid.Parse(authUser.LoginId)
	if err != nil {
		slog.Error("Failed to parse login ID", "err", err)
		return &Response{
			body: "Failed to update username",
			Code: http.StatusBadRequest,
		}
	}

	err = h.profileService.UpdateUsername(r.Context(), profile.UpdateUsernameParams{
		LoginID:     loginId,
		NewUsername: data.NewUsername,
	})

	if err != nil {
		slog.Error("Failed to update username", "err", err)

		// Check for specific error message
		if err.Error() == "username already taken" {
			return &Response{
				Code: http.StatusConflict,
				body: map[string]string{
					"status":  "username_conflict",
					"message": "Username already taken",
				},
			}
		}

		// Handle other errors
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{
				"status":  "internal_error",
				"message": "Failed to update username",
			},
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{
			"message": "Username updated successfully",
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
func (h Handle) AssociateUser(w http.ResponseWriter, r *http.Request) *Response {
	// Extract authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser from context", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Parse the original login ID from the authenticated user
	originalLoginId, err := uuid.Parse(authUser.LoginId)
	if err != nil {
		slog.Error("Failed to parse login ID from auth user", "login_id", authUser.LoginId, "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to parse login ID: " + err.Error(),
		}
	}

	// Decode the request body into AssociateUserJSONRequestBody struct
	data := AssociateUserJSONRequestBody{}
	err = render.DecodeJSON(r.Body, &data)
	if err != nil {
		slog.Error("Failed to decode request body", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: ErrInvalidCredentials,
		}
	}

	// Validate request parameters
	if data.Username == "" || data.Password == "" {
		slog.Error("Missing required credentials", "username_empty", data.Username == "", "password_empty", data.Password == "")
		return &Response{
			Code: http.StatusBadRequest,
			body: ErrInvalidCredentials,
		}
	}

	// Find login by username in the database
	login, err := h.loginService.FindLoginByUsername(r.Context(), data.Username)
	if err != nil {
		if err == pgx.ErrNoRows {
			slog.Error("No login found with username", "username", data.Username)
			return &Response{
				Code: http.StatusBadRequest,
				body: ErrInvalidCredentials,
			}
		}
		slog.Error("Database error finding login with username", "username", data.Username, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: ErrInvalidCredentials,
		}
	}

	slog.Info("Found login with username", "username", data.Username, "login_id", login.ID)

	// Check if the login is already associated with the user
	if login.ID == originalLoginId {
		slog.Warn("Login already associated with user", "login_id", login.ID, "user_id", originalLoginId)
		return &Response{
			Code: http.StatusOK,
			body: "Login already associated with user",
		}
	}

	// Hash the password for logging purposes only (never log actual passwords)
	hashedForLogging := fmt.Sprintf("%x", sha256.Sum256([]byte(data.Password)))
	slog.Info("Verifying password", "password_hash", hashedForLogging)

	// Verify the provided password against the stored hash
	valid, err := h.loginService.CheckPasswordByLoginId(r.Context(), login.ID, data.Password, string(login.Password))
	if err != nil {
		slog.Error("Error during password verification", "login_id", login.ID, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: ErrInvalidCredentials,
		}
	}

	if !valid {
		slog.Error("Invalid password provided", "login_id", login.ID)
		return &Response{
			Code: http.StatusBadRequest,
			body: ErrInvalidCredentials,
		}
	}

	slog.Info("Password verified successfully", "login_id", login.ID)

	// Retrieve all users associated with this login ID
	idmUsers, err := h.profileService.GetUsersByLoginId(r.Context(), login.ID)
	if err != nil {
		slog.Error("Failed to get users by login ID", "login_id", login.ID, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to get users by login ID",
		}
	}

	if len(idmUsers) == 0 {
		slog.Error("No users found for login ID", "login_id", login.ID)
		return &Response{
			Code: http.StatusNotFound,
			body: "No users found for login ID",
		}
	}

	// Check if 2FA is enabled for any of the users associated with this login
	is2FAEnabled, commonMethods, tempToken, err := common.Check2FAEnabled(
		r.Context(),
		w,
		login.ID,
		idmUsers,
		h.twoFaService,
		h.tokenService,
		h.tokenCookieService,
		true, // associate user is true in this API
	)
	if err != nil {
		slog.Error("Failed to check 2FA status", "login_id", login.ID, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to check 2FA status: " + err.Error(),
		}
	}

	// If 2FA is enabled, return a 2FA required response
	if is2FAEnabled {
		slog.Info("2FA required for login association", "login_id", login.ID, "methods", commonMethods)
		return h.prepare2FARequiredResponse(commonMethods, tempToken)
	}

	// If 2FA is not enabled and there are multiple users, return a user selection response
	if len(idmUsers) > 1 {
		return h.prepareUserAssociationSelectionResponse(w, idmUsers[0].UserId, authUser.LoginId, idmUsers, true)
	}

	// If 2FA is not enabled and there is only one user, associate user with current login
	_, err = h.updateUserLoginID(r.Context(), idmUsers[0].UserId, originalLoginId, authUser.DisplayName)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: ErrAssociationFailed + ": " + err.Error(),
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: "User association successful",
	}
}

// CompleteAssociateUser handles the final step of user association after the user has selected which users to associate
// This endpoint processes the user selection and updates the login ID for each selected user
// (POST /users/associate)
func (h Handle) CompleteAssociateUser(w http.ResponseWriter, r *http.Request) *Response {
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed to extract AuthUser from context", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	loginIDStr := authUser.LoginId
	loginID, err := uuid.Parse(loginIDStr)
	if err != nil {
		slog.Error("Failed to parse login ID", "login_id", loginIDStr, "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Failed to parse login ID: " + err.Error(),
		}
	}

	// Parse request body
	data := &CompleteAssociateUserJSONRequestBody{}
	if err := render.DecodeJSON(r.Body, data); err != nil {
		slog.Error("Failed to decode request body", "err", err)
		return &Response{
			Code: http.StatusBadRequest,
			body: "Invalid request body: " + err.Error(),
		}
	}

	// Validate that at least one user is being associated
	if len(data.SelectedUsers) == 0 {
		slog.Error("No users provided for association")
		return &Response{
			Code: http.StatusBadRequest,
			body: "At least one user must be provided for association",
		}
	}

	// Validate the token and extract claims
	token, err := h.validateTokenAndExtractClaims(r, data.LoginID)
	if err != nil {
		return &Response{
			Code: http.StatusUnauthorized,
			body: err.Error(),
		}
	}

	slog.Info("Processing user associations", "user_count", len(data.SelectedUsers), "token_valid", token != nil)

	// Process each user option in the request
	for _, userOption := range data.SelectedUsers {
		// Validate the user ID
		_, err = h.updateUserLoginID(r.Context(), userOption.UserID, loginID, userOption.DisplayName)
		if err != nil {
			return &Response{
				Code: http.StatusInternalServerError,
				body: ErrAssociationFailed + ": " + err.Error(),
			}
		}
	}

	// Prepare success response
	resp := SuccessResponse{
		Result: "Success",
	}

	slog.Info("User association completed successfully", "user_count", len(data.SelectedUsers), "login_id", loginID)
	return CompleteAssociateUserJSON200Response(resp)
}

// Helper method to update a user's login ID in the database
func (h Handle) updateUserLoginID(ctx context.Context, userID string, loginID uuid.UUID, displayName string) (uuid.UUID, error) {
	slog.Info("Associating user with login", "user_id", userID, "login_id", loginID, "display_name", displayName)

	if userID == "" {
		slog.Error("Empty user ID provided")
		return uuid.Nil, fmt.Errorf("user ID cannot be empty")
	}

	// Parse the user ID to ensure it's a valid UUID
	userUuid, err := uuid.Parse(userID)
	if err != nil {
		slog.Error("Invalid user ID format", "user_id", userID, "err", err)
		return uuid.Nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	// Update the user's login ID in the database
	updatedLoginID, err := h.profileService.UpdateLoginId(ctx, profile.UpdateLoginIdParam{
		ID:      userUuid,
		LoginID: utils.ToNullUUID(loginID),
	})
	if err != nil {
		slog.Error("Failed to update login ID for user", "user_id", userID, "login_id", loginID, "err", err)
		return uuid.Nil, err
	}

	slog.Info("User successfully associated with login",
		"user_id", userID,
		"login_id", updatedLoginID,
		"display_name", displayName,
	)

	return updatedLoginID, nil
}

// validateTokenAndExtractClaims validates a temporary token and extracts the necessary claims
// It checks for 2FA verification and login ID match
func (h Handle) validateTokenAndExtractClaims(r *http.Request, expectedLoginID string) (*jwt.Token, error) {
	slog.Info("Validating token and extracting claims")
	// Extract and validate the token from the request
	tempToken, err := r.Cookie(tg.TEMP_TOKEN_NAME)
	if err != nil {
		slog.Error("Failed to get temp token", "err", err)
		return nil, fmt.Errorf("temp token not found")
	}

	// Parse and validate the token
	token, err := h.tokenService.ParseToken(tempToken.Value)
	if err != nil {
		slog.Error("Failed to parse token", "err", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Extract and verify 2FA status from token claims
	twofaVerified, err := common.Get2FAVerifiedFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to verify 2FA status from token claims", "err", err)
		return nil, fmt.Errorf("invalid token claims")
	}

	if !twofaVerified {
		slog.Error("2FA verification required but not completed")
		return nil, fmt.Errorf("2FA verification required")
	}

	// Extract login ID from claims
	loginIDFromClaims, err := common.GetLoginIDFromClaims(token.Claims)
	if err != nil {
		slog.Error("Failed to get login ID from claims", "err", err)
		return nil, fmt.Errorf("invalid token claims")
	}

	slog.Info("Login ID from claims", "login_id", loginIDFromClaims)
	slog.Info("Expected login ID", "expected_login_id", expectedLoginID)

	// If an expected login ID was provided, validate it matches
	if expectedLoginID != "" && loginIDFromClaims != expectedLoginID {
		slog.Error("Login ID from claims does not match expected ID",
			"login_id_from_claims", loginIDFromClaims,
			"expected_login_id", expectedLoginID)
		return nil, fmt.Errorf("invalid token claims")
	}

	return token, nil
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

// prepareTemporaryTokenAndResponse generates a temporary token with claims and prepares a user association selection response
func (h Handle) prepareUserAssociationSelectionResponse(w http.ResponseWriter, userID string, loginID string, users []mapper.User, twoFAVerified bool) *Response {
	// Generate a temporary token with the necessary claims
	extraClaims := map[string]interface{}{
		"login_id":     loginID,
		"2fa_verified": twoFAVerified,
	}
	// Add user options to extra claims if provided
	if users != nil && len(users) > 0 {
		extraClaims["user_options"] = users
	}
	tempTokenMap, err := h.tokenService.GenerateTempToken(userID, nil, extraClaims)
	if err != nil {
		slog.Error("Failed to generate temp token", "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to generate temp token: " + err.Error(),
		}
	}

	// Set the token cookie if a response writer is provided
	if w != nil {
		err = h.tokenCookieService.SetTokensCookie(w, tempTokenMap)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
			return &Response{
				Code: http.StatusInternalServerError,
				body: "Failed to set temp token cookie: " + err.Error(),
			}
		}
	}
	return h.responseHandler.PrepareUserAssociationSelectionResponse(loginID, users)
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

// GetMyDevices retrieves devices linked to the authenticated user's login
// (GET /devices)
func (h Handle) GetMyDevices(w http.ResponseWriter, r *http.Request) *Response {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok || authUser == nil {
		slog.Error("Authentication required", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Get login ID from auth user
	loginID := authUser.LoginID // Already a UUID type

	// Get devices for the login
	devices, err := h.deviceService.FindDevicesByLogin(r.Context(), loginID)
	if err != nil {
		slog.Error("Failed to get devices for login", "error", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{
				"status":  "error",
				"message": "Failed to get devices for login",
				"detail":  err.Error(),
			},
		}
	}

	// Convert devices to DeviceWithLogin
	devicesWithLogin := make([]DeviceWithLogin, 0, len(devices))
	for _, d := range devices {
		// Get the login device link to get expiration information
		loginDevice, err := h.deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), d.Fingerprint, loginID)
		if err != nil {
			slog.Error("Failed to get login device link", "fingerprint", d.Fingerprint, "loginID", loginID, "error", err)
			// Continue with other devices even if we can't get link info for this one
			deviceWithLogin := DeviceWithLogin{
				Fingerprint: d.Fingerprint,
				UserAgent:   d.UserAgent,
				LastLoginAt: d.LastLoginAt,
				CreatedAt:   d.CreatedAt,
				LinkedLogins: []LoginInfo{
					{
						ID:       authUser.LoginId, // Use the string version from authUser
						Username: authUser.DisplayName,
					},
				},
			}
			// Optional fields
			if d.AcceptHeaders != "" {
				acceptHeaders := d.AcceptHeaders
				deviceWithLogin.AcceptHeaders = &acceptHeaders
			}
			if d.Timezone != "" {
				timezone := d.Timezone
				deviceWithLogin.Timezone = &timezone
			}
			if d.ScreenResolution != "" {
				screenRes := d.ScreenResolution
				deviceWithLogin.ScreenResolution = &screenRes
			}
			devicesWithLogin = append(devicesWithLogin, deviceWithLogin)
			continue
		}

		deviceWithLogin := DeviceWithLogin{
			Fingerprint: d.Fingerprint,
			UserAgent:   d.UserAgent,
			LastLoginAt: d.LastLoginAt,
			CreatedAt:   d.CreatedAt,
			LinkedLogins: []LoginInfo{
				{
					ID:       authUser.LoginId, // Use the string version from authUser
					Username: authUser.DisplayName,
				},
			},
		}
		// Optional fields
		if d.AcceptHeaders != "" {
			acceptHeaders := d.AcceptHeaders
			deviceWithLogin.AcceptHeaders = &acceptHeaders
		}
		if d.Timezone != "" {
			timezone := d.Timezone
			deviceWithLogin.Timezone = &timezone
		}
		if d.ScreenResolution != "" {
			screenRes := d.ScreenResolution
			deviceWithLogin.ScreenResolution = &screenRes
		}
		// Set expiration time
		expiresAt := loginDevice.ExpiresAt
		deviceWithLogin.ExpiresAt = &expiresAt
		devicesWithLogin = append(devicesWithLogin, deviceWithLogin)
	}

	// Return success response
	response := ListDevicesResponse{
		Status:  "success",
		Message: "Devices retrieved successfully",
		Devices: devicesWithLogin,
	}
	return &Response{
		Code:        http.StatusOK,
		body:        response,
		contentType: "application/json",
	}
}

// ResponseHandler defines the interface for handling responses during login
type ResponseHandler interface {
	// PrepareUserListResponse prepares a response for a list of users
	PrepareUserListResponse(users []mapper.User) *Response
	// PrepareUserSwitchResponse prepares a response for user switch
	PrepareUserSwitchResponse(users []mapper.User) *Response
	// PrepareUserAssociationSelectionResponse prepares a response for user association selection
	PrepareUserAssociationSelectionResponse(loginID string, users []mapper.User) *Response
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

// PrepareUserAssociationSelectionResponse prepares a response for user association selection
func (h *DefaultResponseHandler) PrepareUserAssociationSelectionResponse(loginID string, users []mapper.User) *Response {

	// Convert users to user options
	userOptions := []UserOption{}

	for _, user := range users {
		email, _ := user.ExtraClaims["email"].(string)
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}
		userOptions = append(userOptions, UserOption{
			UserID:      user.UserId,
			DisplayName: user.DisplayName,
			Email:       email,
		})
	}

	// Prepare the response with user options for selection
	resp := SelectUsersToAssociateRequiredResponse{
		LoginID:     loginID,
		Status:      "user_association_selection_required",
		UserOptions: userOptions,
		Message:     "Please select which user to use for this account",
	}

	slog.Info("Returning user selection options", "login_id", loginID, "option_count", len(users))
	return &Response{
		Code:        http.StatusAccepted,
		body:        resp,
		contentType: "application/json",
	}
}
