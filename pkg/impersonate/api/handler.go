package impersonate

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/impersonate"
	"github.com/tendant/simple-idm/pkg/login/api"
	"github.com/tendant/simple-idm/pkg/mapper"
)

// Constants for token cookie names
const (
	ACCESS_TOKEN_NAME  = api.ACCESS_TOKEN_NAME
	REFRESH_TOKEN_NAME = api.REFRESH_TOKEN_NAME
)

// Handler implements the ServerInterface for impersonate API
type Handle struct {
	service    *impersonate.Service
	jwtService auth.Jwt
}

// TokenInfo contains token and its expiry time
type TokenInfo struct {
	Token  string
	Expiry time.Time
}

// NewHandler creates a new impersonate API handler
func NewHandler(service *impersonate.Service, jwtService auth.Jwt) *Handle {
	return &Handle{
		service:    service,
		jwtService: jwtService,
	}
}

// CreateImpersonate handles the POST /impersonate endpoint
// It creates an impersonation session allowing a delegatee to access a delegator's account
func (h *Handle) CreateImpersonate(w http.ResponseWriter, r *http.Request) *Response {
	// Get the current user from context (this would be set by your auth middleware)
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed to get authenticated user from context")
		return CreateImpersonateJSON401Response(ErrorResponse{
			Error: "Unauthorized",
			Code:  stringPtr("unauthorized"),
		})
	}

	// Use the LoginID from authUser
	loginUuid := authUser.LoginID

	// Parse request body
	var reqBody CreateImpersonateJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		return CreateImpersonateJSON400Response(ErrorResponse{
			Error: "Invalid request body",
			Code:  stringPtr("invalid_request"),
		})
	}

	// Validate delegator_user_uuid
	delegatorUserUUID, err := uuid.Parse(reqBody.DelegatorUserUUID)
	if err != nil {
		slog.Error("Invalid delegator_user_uuid", "error", err)
		return CreateImpersonateJSON400Response(ErrorResponse{
			Error: "Invalid delegator user UUID",
			Code:  stringPtr("invalid_uuid"),
		})
	}

	// Get delegated users for the current user
	delegatedUsers, err := h.service.GetDelegatedUsers(r.Context(), loginUuid)
	if err != nil {
		slog.Error("Failed to get delegated users", "error", err, "user_id", loginUuid)
		return CreateImpersonateJSON403Response(ErrorResponse{
			Error: "Failed to get delegated users",
			Code:  stringPtr("server_error"),
		})
	}

	// Check if the requested delegator is in the list of delegated users
	var foundDelegator bool
	var selectedUser struct {
		UUID       string
		Fullname   string
		Email      string
		Role       string
		TenantUUID string
	}

	for _, user := range delegatedUsers {
		if user.UserId == delegatorUserUUID.String() {
			foundDelegator = true
			selectedUser.UUID = user.UserId
			selectedUser.Fullname = user.DisplayName
			break
		}
	}

	if !foundDelegator {
		slog.Error("User not authorized to impersonate the requested delegator", "delegator_uuid", delegatorUserUUID)
		return CreateImpersonateJSON403Response(ErrorResponse{
			Error: "Not authorized to impersonate this user",
			Code:  stringPtr("forbidden"),
		})
	}

	// TODO: Generate actual tokens for the impersonation session
	// This would typically involve your JWT or token service

	// Create a mappedUser for token generation
	mappedUser := mapper.User{
		// delegator user uuid
		UserId: selectedUser.UUID,
		// current user's login id
		LoginID:     loginUuid.String(),
		DisplayName: selectedUser.Fullname,
	}

	// Generate access token
	accessToken, err := h.jwtService.CreateAccessToken(mappedUser)
	if err != nil {
		slog.Error("Failed to create access token", "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	// Generate refresh token
	refreshToken, err := h.jwtService.CreateRefreshToken(mappedUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	// Set cookies for the tokens
	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	// Return the success response with user information
	return CreateImpersonateJSON200Response(SuccessResponse{})
}

// CreateImpersonateBack handles the POST /impersonate/back endpoint
// It ends the current impersonation session and returns to the original user context
func (h *Handle) CreateImpersonateBack(w http.ResponseWriter, r *http.Request) *Response {
	// Get the current user from context (this would be set by your auth middleware)
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		slog.Error("Failed to get authenticated user from context")
		return CreateImpersonateBackJSON401Response(ErrorResponse{
			Error: "Unauthorized",
			Code:  stringPtr("unauthorized"),
		})
	}

	// Use the LoginID from authUser
	loginId := authUser.LoginID

	// Check if the current user is in an impersonation session
	// This would typically involve checking a token or session store
	// For now, we'll assume the user is in an impersonation session if they call this endpoint

	// TODO: Implement the actual logic to end impersonation
	// 1. Verify that the current user is in an impersonation session
	// 2. Generate tokens to return to the original user context
	// 3. Return the tokens and original user information

	// Create a mappedUser for token generation

	originalUser, err := h.service.GetOriginalUser(r.Context(), loginId)
	if err != nil {
		slog.Error("Failed to get original user", "error", err)
		return &Response{
			body: "Failed to get original user",
			Code: http.StatusInternalServerError,
		}
	}

	mappedUser := mapper.User{
		// original user uuid
		UserId: originalUser.UserId,
		// original user login id
		LoginID: originalUser.LoginID,
		// original user display name
		DisplayName: originalUser.DisplayName,
	}

	// Generate access token
	accessToken, err := h.jwtService.CreateAccessToken(mappedUser)
	if err != nil {
		slog.Error("Failed to create access token", "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	// Generate refresh token
	refreshToken, err := h.jwtService.CreateRefreshToken(mappedUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	// Set cookies for the tokens
	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	// Return the success response with the original user's information
	return CreateImpersonateBackJSON200Response(SuccessResponse{})
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}

// setTokenCookie sets a cookie with the given name, value, and expiry time
func (h *Handle) setTokenCookie(w http.ResponseWriter, name, value string, expiry time.Time) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiry,
	}
	http.SetCookie(w, cookie)
}
