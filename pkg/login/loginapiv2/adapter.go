package loginapiv2

import (
	"context"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/mapper"
	"github.com/tendant/simple-idm/pkg/utils"
)

// LoginService is an adapter for the domain login service
type LoginService struct {
	domainService *login.LoginService
}

// LoginParams represents parameters for login operations
type LoginParams struct {
	Email    string
	Username string
}

// RegisterParam represents parameters for user registration
type RegisterParam struct {
	Email    string
	Name     string
	Password string
}

// NewLoginService creates a new login service adapter
func NewLoginService(domainService *login.LoginService) *LoginService {
	return &LoginService{
		domainService: domainService,
	}
}

// Login authenticates a user and returns user information
func (s *LoginService) Login(ctx context.Context, username, password string) (login.LoginResult, error) {
	return s.domainService.Login(ctx, username, password)
}

// GetUsersByLoginId returns users associated with a login ID
func (s *LoginService) GetUsersByLoginId(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error) {
	return s.domainService.GetUsersByLoginId(ctx, loginID)
}

// CheckPasswordByLoginId verifies a password for a login ID
func (s *LoginService) CheckPasswordByLoginId(ctx context.Context, loginId uuid.UUID, password, hashedPassword string) (bool, error) {
	return s.domainService.CheckPasswordByLoginId(ctx, loginId, password, hashedPassword)
}

// Verify2FACode verifies a 2FA code
func (s *LoginService) Verify2FACode(ctx context.Context, loginId string, code string) (bool, error) {
	return s.domainService.Verify2FACode(ctx, loginId, code)
}

// Create registers a new user
func (s *LoginService) Create(ctx context.Context, params RegisterParam) error {
	domainParams := login.RegisterParam{
		Email:    params.Email,
		Name:     params.Name,
		Password: params.Password,
	}
	_, err := s.domainService.Create(ctx, domainParams)
	return err
}

// EmailVerify verifies an email address
func (s *LoginService) EmailVerify(ctx context.Context, email string) error {
	return s.domainService.EmailVerify(ctx, email)
}

// FindUserRoles finds roles for a user
func (s *LoginService) FindUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.domainService.FindUserRoles(ctx, userID)
}

// InitPasswordReset initiates a password reset
func (s *LoginService) InitPasswordReset(ctx context.Context, username string) error {
	return s.domainService.InitPasswordReset(ctx, username)
}

// ResetPassword resets a password using a token
func (s *LoginService) ResetPassword(ctx context.Context, token, newPassword string) error {
	return s.domainService.ResetPassword(ctx, token, newPassword)
}

// GetPasswordPolicy returns the password policy
func (s *LoginService) GetPasswordPolicy() *login.PasswordPolicy {
	return s.domainService.GetPasswordPolicy()
}

// SendUsernameEmail sends an email with the username
func (s *LoginService) SendUsernameEmail(ctx context.Context, email, username string) error {
	return s.domainService.SendUsernameEmail(ctx, email, username)
}

// FindUsernameByEmail finds a username by email address
func (s *LoginService) FindUsernameByEmail(ctx context.Context, email string) (string, bool, error) {
	return s.domainService.FindUsernameByEmail(ctx, email)
}

// GetPasswordManager returns the password manager from the domain service
func (s *LoginService) GetPasswordManager() *login.PasswordManager {
	return s.domainService.GetPasswordManager()
}

// GetRepository returns the repository from the domain service
func (s *LoginService) GetRepository() login.LoginRepository {
	return s.domainService.GetRepository()
}

// Using DeliveryOption from generated code

// Helper function to get unique emails from users
func getUniqueEmailsFromUsers(users []mapper.User) []DeliveryOption {
	emailMap := make(map[string]bool)
	var deliveryOptions []DeliveryOption

	for _, user := range users {
		// Get email from UserInfo
		email := user.UserInfo.Email
		if emailMap[email] || email == "" {
			continue
		}

		deliveryOptions = append(deliveryOptions, DeliveryOption{
			UserID:       user.UserId,
			DisplayValue: utils.MaskEmail(email),
			HashedValue:  utils.HashEmail(email),
		})
		emailMap[email] = true
	}

	return deliveryOptions
}
