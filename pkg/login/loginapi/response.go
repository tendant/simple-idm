package loginapi

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-idm/pkg/loginflow"
	"github.com/tendant/simple-idm/pkg/mapper"
	tg "github.com/tendant/simple-idm/pkg/tokengenerator"
)

// Response status constants
const (
	STATUS_SUCCESS                    = "success"
	STATUS_MULTIPLE_USERS             = "multiple_users"
	STATUS_USER_ASSOCIATION_REQUIRED  = "user_association_required"
	STATUS_USER_ASSOCIATION_SELECTION = "user_association_selection_required"
	STATUS_2FA_REQUIRED               = "2fa_required"
	STATUS_ACCOUNT_LOCKED             = "account_locked"
	STATUS_PASSWORD_EXPIRED           = "password_expired"
	STATUS_PASSWORD_ABOUT_TO_EXPIRE   = "password_about_to_expire"
)

// ResponseHandler defines the interface for handling responses during login
type ResponseHandler interface {
	// PrepareUserSelectionResponse converts IDM users to API users for selection
	PrepareUserSelectionResponse(idmUsers []mapper.User, loginID uuid.UUID, tempTokenStr string) *Response
	// PrepareUserListResponse prepares a response for a list of users
	PrepareUserListResponse(users []mapper.User) *Response
	// PrepareUserSwitchResponse prepares a response for user switch
	PrepareUserSwitchResponse(users []mapper.User) *Response
	// PrepareTokenResponse prepares a response with access and refresh tokens
	PrepareTokenResponse(tokens map[string]tg.TokenValue) *Response
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

// PrepareUserSelectionResponse creates a response for user selection
func (h *DefaultResponseHandler) PrepareUserSelectionResponse(idmUsers []mapper.User, loginID uuid.UUID, tempTokenStr string) *Response {
	apiUsers := make([]User, len(idmUsers))
	for i, mu := range idmUsers {
		email := mu.UserInfo.Email
		name := mu.DisplayName
		id := mu.UserId

		// Use the Roles field directly - it's always populated and safe
		roles := mu.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers[i] = User{
			ID:    id,
			Email: email,
			Name:  name,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
		}
	}

	return PostLoginJSON202Response(SelectUserRequiredResponse{
		Status:    STATUS_MULTIPLE_USERS,
		Message:   "Multiple users found, please select one",
		TempToken: tempTokenStr,
		Users:     apiUsers,
	})
}

// PrepareUserListResponse prepares a response for a list of users
func (h *DefaultResponseHandler) PrepareUserListResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email := user.UserInfo.Email
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		// Use the Roles field directly - it's always populated and safe
		roles := user.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
			Email: email,
		})
	}
	return FindUsersWithLoginJSON200Response(apiUsers)
}

// PrepareUserSwitchResponse prepares a response for user switch
func (h *DefaultResponseHandler) PrepareUserSwitchResponse(users []mapper.User) *Response {
	var apiUsers []User
	for _, user := range users {
		email := user.UserInfo.Email
		// Check if email is available in UserInfo
		if user.UserInfo.Email != "" {
			email = user.UserInfo.Email
		}

		// Use the Roles field directly - it's always populated and safe
		roles := user.Roles
		var firstRole string
		if len(roles) > 0 {
			firstRole = roles[0]
		}

		apiUsers = append(apiUsers, User{
			ID:    user.UserId,
			Name:  user.DisplayName,
			Role:  firstRole, // Backward compatibility
			Roles: roles,     // New array field
			Email: email,
		})
	}

	response := Login{
		Status:  STATUS_SUCCESS,
		Message: "Successfully switched user",
		Users:   apiUsers,
	}

	return PostUserSwitchJSON200Response(response)
}

// PrepareTokenResponse creates a response with access and refresh tokens
func (h *DefaultResponseHandler) PrepareTokenResponse(tokens map[string]tg.TokenValue) *Response {
	accessToken, hasAccess := tokens[tg.ACCESS_TOKEN_NAME]
	refreshToken, hasRefresh := tokens[tg.REFRESH_TOKEN_NAME]

	if !hasAccess || !hasRefresh {
		slog.Error("Missing required tokens", "has_access", hasAccess, "has_refresh", hasRefresh)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Internal server error: insufficient tokens",
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: LoginResponse{
			AccessToken:  accessToken.Token,
			RefreshToken: refreshToken.Token,
		},
		contentType: "application/json",
	}
}

// PrepareUserAssociationSelectionResponse prepares a response for user association selection
func (h *DefaultResponseHandler) PrepareUserAssociationSelectionResponse(loginID string, users []mapper.User) *Response {
	// Convert mapper.User objects to UserOption objects
	var userOptions []UserOption
	for _, user := range users {
		option := UserOption{
			UserID:      user.UserId,
			DisplayName: user.DisplayName,
			Email:       user.UserInfo.Email,
		}

		userOptions = append(userOptions, option)
	}

	// Prepare the response with user options for selection
	resp := SelectUsersToAssociateRequiredResponse{
		Status:      STATUS_USER_ASSOCIATION_SELECTION,
		Message:     "Please select users to associate",
		LoginID:     loginID,
		UserOptions: userOptions,
	}

	slog.Info("Returning user selection options", "login_id", loginID, "option_count", len(users))
	return &Response{
		Code:        http.StatusAccepted,
		body:        resp,
		contentType: "application/json",
	}
}

// mapErrorToHTTPResponse maps loginflow service errors to HTTP responses
func (h Handle) mapErrorToHTTPResponse(err *loginflow.Error) *Response {
	switch err.Type {
	case loginflow.ErrorTypeAccountLocked:
		return &Response{
			Code:        http.StatusTooManyRequests,
			body:        err.Message,
			contentType: "application/json",
		}
	case loginflow.ErrorTypePasswordExpired:
		return &Response{
			Code:        http.StatusForbidden,
			body:        err.Message,
			contentType: "application/json",
		}
	case loginflow.ErrorTypeInvalidCredentials:
		return &Response{
			Code: http.StatusBadRequest,
			body: err.Message,
		}
	case loginflow.ErrorTypeNoUserFound:
		return &Response{
			Code: http.StatusForbidden,
			body: err.Message,
		}
	case loginflow.ErrorTypeInternalError:
		return &Response{
			Code: http.StatusInternalServerError,
			body: err.Message,
		}
	default:
		return &Response{
			Code: http.StatusInternalServerError,
			body: "An unexpected error occurred",
		}
	}
}

// prepare2FARequiredResponse prepares a 2FA required response
// helper method for login handler, private since no need for separate implementation
func (h Handle) prepare2FARequiredResponse(w http.ResponseWriter, commonMethods []loginflow.TwoFactorMethod, tempTokenMap map[string]tg.TokenValue) *Response {
	// Convert common.TwoFactorMethod to api.TwoFactorMethod
	var twoFactorMethods []TwoFactorMethod
	slog.Info("temp token generated")
	err := copier.Copy(&twoFactorMethods, &commonMethods)
	if err != nil {
		slog.Error("Failed to copy 2FA methods", "err", err)
		return &Response{
			body: "Failed to process 2FA methods",
			Code: http.StatusInternalServerError,
		}
	}

	// Only set cookie if a writer is provided (web flow)
	if w != nil {
		err = h.tokenCookieService.SetTokensCookie(w, tempTokenMap)
		if err != nil {
			slog.Error("Failed to set temp token cookie", "err", err)
		}
	}

	twoFARequiredResp := TwoFactorRequiredResponse{
		TempToken:        tempTokenMap[tg.TEMP_TOKEN_NAME].Token,
		TwoFactorMethods: twoFactorMethods,
		Status:           STATUS_2FA_REQUIRED,
		Message:          "Two-factor authentication is required",
	}

	return &Response{
		Code: http.StatusAccepted,
		body: twoFARequiredResp,
	}
}

// prepareUserAssociationSelectionResponse prepares a response for user association selection
// It uses the loginflow service to generate a temporary token and returns a properly formatted response
func (h Handle) prepareUserAssociationSelectionResponse(w http.ResponseWriter, loginID, userID string, userOptions []mapper.User) *Response {
	// Validate user options
	if userOptions == nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "No users found with login provided",
		}
	}

	// Use loginflow service to generate the temp token
	tempTokenMap, err := h.loginFlowService.GenerateUserAssociationToken(loginID, userID, userOptions)
	if err != nil {
		slog.Error("Failed to generate user association token", "err", err)
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

	if len(userOptions) > 1 {
		return h.responseHandler.PrepareUserAssociationSelectionResponse(loginID, userOptions)
	}

	user := UserOption{
		UserID:      userOptions[0].UserId,
		DisplayName: userOptions[0].DisplayName,
		Email:       userOptions[0].UserInfo.Email,
	}

	resp := AssociateUserResponse{
		Status:     STATUS_USER_ASSOCIATION_REQUIRED,
		Message:    "Please call user association endpoint",
		LoginID:    loginID,
		UserOption: user,
	}

	return &Response{
		Code:        http.StatusAccepted,
		body:        resp,
		contentType: "application/json",
	}

}
