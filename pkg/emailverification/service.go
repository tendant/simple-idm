package emailverification

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/notification"
)

// EmailVerificationService handles email verification operations
type EmailVerificationService struct {
	repo                *Repository
	notificationManager *notification.NotificationManager
	baseURL             string
	tokenExpiry         time.Duration
	resendLimit         int
	resendWindow        time.Duration
}

// EmailVerificationServiceOption defines configuration options
type EmailVerificationServiceOption func(*EmailVerificationService)

// WithTokenExpiry sets the token expiration duration
func WithTokenExpiry(expiry time.Duration) EmailVerificationServiceOption {
	return func(s *EmailVerificationService) {
		s.tokenExpiry = expiry
	}
}

// WithResendLimit sets the maximum number of emails that can be sent within the resend window
func WithResendLimit(limit int) EmailVerificationServiceOption {
	return func(s *EmailVerificationService) {
		s.resendLimit = limit
	}
}

// WithResendWindow sets the time window for rate limiting
func WithResendWindow(window time.Duration) EmailVerificationServiceOption {
	return func(s *EmailVerificationService) {
		s.resendWindow = window
	}
}

// NewEmailVerificationService creates a new email verification service
func NewEmailVerificationService(
	repo *Repository,
	notificationManager *notification.NotificationManager,
	baseURL string,
	opts ...EmailVerificationServiceOption,
) *EmailVerificationService {
	service := &EmailVerificationService{
		repo:                repo,
		notificationManager: notificationManager,
		baseURL:             baseURL,
		tokenExpiry:         24 * time.Hour, // Default 24 hours
		resendLimit:         3,               // Default 3 emails per window
		resendWindow:        1 * time.Hour,   // Default 1 hour window
	}

	for _, opt := range opts {
		opt(service)
	}

	return service
}

// generateToken generates a cryptographically secure random token
func generateToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CreateVerificationToken creates a new verification token and sends the verification email
func (s *EmailVerificationService) CreateVerificationToken(ctx context.Context, userID uuid.UUID, userName, userEmail string) (string, error) {
	// Check if user exists and get status
	user, err := s.repo.GetUserEmailVerificationStatus(ctx, userID)
	if err != nil {
		slog.Error("Failed to get user", "user_id", userID, "error", err)
		return "", ErrUserNotFound
	}

	// Check if already verified
	if user.EmailVerified {
		slog.Info("Email already verified", "user_id", userID)
		return "", ErrEmailAlreadyVerified
	}

	// Check rate limit
	cutoffTime := time.Now().UTC().Add(-s.resendWindow)
	count, err := s.repo.CountRecentTokensByUserId(ctx, userID, cutoffTime)
	if err != nil {
		slog.Error("Failed to count recent tokens", "user_id", userID, "error", err)
		return "", fmt.Errorf("failed to check rate limit: %w", err)
	}

	if count >= int64(s.resendLimit) {
		slog.Warn("Rate limit exceeded", "user_id", userID, "count", count, "limit", s.resendLimit)
		return "", ErrRateLimitExceeded
	}

	// Generate token
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	// Calculate expiry
	expiresAt := time.Now().UTC().Add(s.tokenExpiry)

	// Create token in database
	dbToken, err := s.repo.CreateVerificationToken(ctx, userID, token, expiresAt)
	if err != nil {
		slog.Error("Failed to create verification token", "user_id", userID, "error", err)
		return "", fmt.Errorf("failed to create verification token: %w", err)
	}

	// Send verification email
	verificationLink := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

	err = s.sendVerificationEmail(ctx, userEmail, userName, verificationLink)
	if err != nil {
		slog.Error("Failed to send verification email", "user_id", userID, "error", err)
		// Don't return error - token is created, email sending is best effort
	}

	slog.Info("Verification token created", "user_id", userID, "token_id", dbToken.ID, "expires_at", expiresAt)
	return token, nil
}

// VerifyEmail verifies an email using the provided token
func (s *EmailVerificationService) VerifyEmail(ctx context.Context, token string) error {
	// Get token from database
	dbToken, err := s.repo.GetVerificationTokenByToken(ctx, token)
	if err != nil {
		slog.Error("Failed to get verification token", "error", err)
		return ErrTokenNotFound
	}

	// Check if token has expired
	if time.Now().UTC().After(dbToken.ExpiresAt) {
		slog.Warn("Token expired", "token_id", dbToken.ID, "expires_at", dbToken.ExpiresAt)
		return ErrTokenExpired
	}

	// Check if token was already used
	if dbToken.VerifiedAt != nil {
		slog.Warn("Token already used", "token_id", dbToken.ID, "verified_at", *dbToken.VerifiedAt)
		return ErrTokenAlreadyUsed
	}

	// Mark user email as verified
	err = s.repo.MarkUserEmailAsVerified(ctx, dbToken.UserID)
	if err != nil {
		slog.Error("Failed to mark user email as verified", "user_id", dbToken.UserID, "error", err)
		return fmt.Errorf("failed to verify email: %w", err)
	}

	// Mark token as verified
	err = s.repo.MarkTokenAsVerified(ctx, dbToken.ID)
	if err != nil {
		slog.Error("Failed to mark token as verified", "token_id", dbToken.ID, "error", err)
		// Don't return error - user email is already marked as verified
	}

	// Soft delete all other tokens for this user
	err = s.repo.SoftDeleteUserTokens(ctx, dbToken.UserID)
	if err != nil {
		slog.Error("Failed to soft delete user tokens", "user_id", dbToken.UserID, "error", err)
		// Don't return error - verification succeeded
	}

	slog.Info("Email verified successfully", "user_id", dbToken.UserID, "token_id", dbToken.ID)
	return nil
}

// ResendVerificationEmail resends the verification email to a user
func (s *EmailVerificationService) ResendVerificationEmail(ctx context.Context, userID uuid.UUID, userName, userEmail string) error {
	// Check if user exists and get status
	user, err := s.repo.GetUserEmailVerificationStatus(ctx, userID)
	if err != nil {
		slog.Error("Failed to get user", "user_id", userID, "error", err)
		return ErrUserNotFound
	}

	// Check if already verified
	if user.EmailVerified {
		slog.Info("Email already verified", "user_id", userID)
		return ErrEmailAlreadyVerified
	}

	// If email or name not provided, use from database
	if userEmail == "" {
		userEmail = user.Email
	}
	if userName == "" {
		userName = user.Name
	}

	// Soft delete existing active tokens
	err = s.repo.SoftDeleteUserTokens(ctx, userID)
	if err != nil {
		slog.Error("Failed to delete existing tokens", "user_id", userID, "error", err)
		// Continue anyway
	}

	// Create new token (this also sends the email)
	_, err = s.CreateVerificationToken(ctx, userID, userName, userEmail)
	return err
}

// GetVerificationStatus returns the email verification status for a user
func (s *EmailVerificationService) GetVerificationStatus(ctx context.Context, userID uuid.UUID) (bool, *time.Time, error) {
	user, err := s.repo.GetUserEmailVerificationStatus(ctx, userID)
	if err != nil {
		slog.Error("Failed to get user verification status", "user_id", userID, "error", err)
		return false, nil, ErrUserNotFound
	}

	return user.EmailVerified, user.EmailVerifiedAt, nil
}

// CleanupExpiredTokens soft deletes all expired verification tokens
func (s *EmailVerificationService) CleanupExpiredTokens(ctx context.Context) error {
	err := s.repo.CleanupExpiredTokens(ctx)
	if err != nil {
		slog.Error("Failed to cleanup expired tokens", "error", err)
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	slog.Info("Expired tokens cleaned up successfully")
	return nil
}

// sendVerificationEmail sends the verification email
func (s *EmailVerificationService) sendVerificationEmail(ctx context.Context, email, name, verificationLink string) error {
	if s.notificationManager == nil {
		slog.Warn("Notification manager not configured, skipping email send")
		return nil
	}

	notificationData := notification.NotificationData{
		To: email,
		Data: map[string]string{
			"Name":             name,
			"VerificationLink": verificationLink,
			"ExpiryHours":      fmt.Sprintf("%.0f", s.tokenExpiry.Hours()),
		},
	}

	// Note: The NoticeType constant will be defined in pkg/notice/service.go
	err := s.notificationManager.Send("email_verification", notificationData)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}
