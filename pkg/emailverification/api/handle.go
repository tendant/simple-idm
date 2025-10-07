package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/emailverification"
)

// Handler implements the ServerInterface for email verification API
type Handler struct {
	service *emailverification.EmailVerificationService
}

// NewHandler creates a new email verification API handler
func NewHandler(service *emailverification.EmailVerificationService) *Handler {
	return &Handler{
		service: service,
	}
}

// VerifyEmail handles POST /verify
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrorResponse{Error: "Invalid request body"})
		return
	}

	// Validate token
	if req.Token == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrorResponse{Error: "Token is required"})
		return
	}

	// Verify email
	err := h.service.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		status := http.StatusBadRequest
		message := "Failed to verify email"

		switch {
		case errors.Is(err, emailverification.ErrTokenNotFound):
			status = http.StatusNotFound
			message = "Invalid verification token"
		case errors.Is(err, emailverification.ErrTokenExpired):
			status = http.StatusBadRequest
			message = "Verification token has expired"
		case errors.Is(err, emailverification.ErrTokenAlreadyUsed):
			status = http.StatusBadRequest
			message = "Verification token has already been used"
		default:
			slog.Error("Failed to verify email", "error", err)
			status = http.StatusInternalServerError
			message = "An error occurred while verifying email"
		}

		render.Status(r, status)
		render.JSON(w, r, ErrorResponse{Error: message})
		return
	}

	// Return success response
	render.Status(r, http.StatusOK)
	render.JSON(w, r, VerifyEmailResponse{
		Message:    "Email verified successfully",
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// ResendVerification handles POST /resend
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT token
	userID, err := getUserIDFromContext(r)
	if err != nil {
		slog.Error("Failed to get user ID from context", "error", err)
		render.Status(r, http.StatusUnauthorized)
		render.JSON(w, r, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse request body (optional user_id override for admins)
	var req ResendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.UserId != nil {
		// If user_id is provided in request, use it (TODO: add admin check)
		parsedID, err := uuid.Parse(*req.UserId)
		if err == nil {
			userID = parsedID
		}
	}

	// Get user info for the email (we need name and email)
	// TODO: Fetch user info from IAM service
	// For now, we'll need to pass empty strings and the service will fetch from DB
	err = h.service.ResendVerificationEmail(r.Context(), userID, "", "")
	if err != nil {
		status := http.StatusBadRequest
		message := "Failed to send verification email"

		switch {
		case errors.Is(err, emailverification.ErrUserNotFound):
			status = http.StatusNotFound
			message = "User not found"
		case errors.Is(err, emailverification.ErrAlreadyVerified):
			status = http.StatusBadRequest
			message = "Email is already verified"
		case errors.Is(err, emailverification.ErrRateLimitExceeded):
			status = http.StatusTooManyRequests
			message = "Too many verification emails sent. Please try again later"
		default:
			slog.Error("Failed to resend verification email", "error", err)
			status = http.StatusInternalServerError
			message = "An error occurred while sending verification email"
		}

		render.Status(r, status)
		render.JSON(w, r, ErrorResponse{Error: message})
		return
	}

	// Return success response
	render.Status(r, http.StatusOK)
	render.JSON(w, r, ResendVerificationResponse{
		Message: "Verification email sent successfully",
	})
}

// GetVerificationStatus handles GET /status
func (h *Handler) GetVerificationStatus(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT token
	userID, err := getUserIDFromContext(r)
	if err != nil {
		slog.Error("Failed to get user ID from context", "error", err)
		render.Status(r, http.StatusUnauthorized)
		render.JSON(w, r, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Get verification status
	verified, verifiedAt, err := h.service.GetVerificationStatus(r.Context(), userID)
	if err != nil {
		status := http.StatusNotFound
		message := "User not found"

		if !errors.Is(err, emailverification.ErrUserNotFound) {
			slog.Error("Failed to get verification status", "error", err)
			status = http.StatusInternalServerError
			message = "An error occurred while retrieving verification status"
		}

		render.Status(r, status)
		render.JSON(w, r, ErrorResponse{Error: message})
		return
	}

	// Prepare response
	response := VerificationStatusResponse{
		EmailVerified: verified,
	}

	if verifiedAt != nil {
		verifiedAtStr := verifiedAt.Format(time.RFC3339)
		response.VerifiedAt = &verifiedAtStr
	}

	// Return success response
	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// getUserIDFromContext extracts the user ID from the JWT token in the request context
func getUserIDFromContext(r *http.Request) (uuid.UUID, error) {
	// Try to get JWT token from context (set by jwtauth middleware)
	token, ok := r.Context().Value("jwt").(*jwt.Token)
	if !ok || token == nil {
		return uuid.Nil, errors.New("no JWT token found in context")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, errors.New("invalid JWT claims")
	}

	// Get user_id from claims
	userIDStr, ok := claims["user_id"].(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, errors.New("user_id not found in JWT claims")
	}

	// Parse UUID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, errors.New("invalid user_id in JWT claims")
	}

	return userID, nil
}
