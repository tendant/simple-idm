package auth

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tendant/simple-idm/pkg/login"
)

type (
	MatchPassParam struct {
		UserUuid uuid.UUID
		Password string
	}
	UpdatePassParam struct {
		UserUuid    uuid.UUID
		NewPassword string
	}
)

type (
	AuthLogin interface {
		MatchPasswordByUuids(ctx context.Context, param MatchPassParam) (bool, error)
		VerifyPasswordComplexity(ctx context.Context, password string) error
		UpdatePassword(ctx context.Context, param UpdatePassParam) error
	}
)

type (
	PasswordComplexity struct {
		RequiredDigit           bool
		RequiredLowercase       bool
		RequiredUppercase       bool
		RequiredNonAlphanumeric bool
		RequiredLength          int
	}
)

type AuthLoginService struct {
	repo         AuthRepository
	loginService *login.LoginService
	pwdComplex   PasswordComplexity
}

func NewAuthLoginService(repo AuthRepository, loginService *login.LoginService) *AuthLoginService {
	return &AuthLoginService{
		repo:         repo,
		loginService: loginService,
	}
}

func WithPwdComplex(pwdComplex PasswordComplexity) func(*AuthLoginService) {
	return func(svc *AuthLoginService) {
		svc.pwdComplex = pwdComplex
	}
}

func (authSvc AuthLoginService) VerifyPasswordComplexity(ctx context.Context, password string) error {
	requireDigit := authSvc.pwdComplex.RequiredDigit
	requireLowercase := authSvc.pwdComplex.RequiredLowercase
	requireNonAlphanumeric := authSvc.pwdComplex.RequiredNonAlphanumeric
	requireUppercase := authSvc.pwdComplex.RequiredUppercase
	requiredLength := authSvc.pwdComplex.RequiredLength

	hasDigit := regexp.MustCompile(`[0-9]+`)
	hasLowercase := regexp.MustCompile(`[a-z]+`)
	hasUppercase := regexp.MustCompile(`[A-Z]+`)
	hasNonAlphanumeric := regexp.MustCompile(`[\W_]+`)

	if requireDigit && !hasDigit.MatchString(password) {
		return errors.New("password complexity is not satisfied. Passwords must have at least one digit ('0'-'9')")
	}
	if requireLowercase && !hasLowercase.MatchString(password) {
		return errors.New("password complexity is not satisfied. Passwords must have at least one lowercase ('a'-'z')")
	}
	if requireUppercase && !hasUppercase.MatchString(password) {
		return errors.New("password complexity is not satisfied. Passwords must have at least one uppercase ('A'-'Z')")
	}
	if requireNonAlphanumeric && !hasNonAlphanumeric.MatchString(password) {
		return errors.New("password complexity is not satisfied. Passwords must have at least one non-alphanumeric character")
	}
	if len(password) < requiredLength {
		return errors.New("password complexity is not satisfied. Passwords must be at least " + strconv.Itoa(requiredLength) + " characters")
	}
	return nil
}

func (authSvc AuthLoginService) MatchPasswordByUuids(ctx context.Context, param MatchPassParam) (bool, error) {
	userAuthEntity, err := authSvc.repo.FindUserByUserUUID(ctx, param.UserUuid)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Error("User not found", "user uuid", param.UserUuid)
		return false, errors.New("user not found")
	} else if err != nil {
		slog.Error("Failed to find user record", "user uuid", param.UserUuid, "err", err)
		return false, err
	}

	if !userAuthEntity.PasswordValid {
		slog.Error("User has no password set", "user uuid", param.UserUuid)
		return false, errors.New("user has no password set")
	}

	return authSvc.loginService.CheckPasswordHash(param.Password, userAuthEntity.Password, login.PasswordV1)
}

func (authSvc AuthLoginService) UpdatePassword(ctx context.Context, param UpdatePassParam) error {
	// Hash the password using the login service
	hashedPassword, err := authSvc.loginService.HashPassword(param.NewPassword)
	if err != nil {
		slog.Error("Failed to generate password hash", "err", err)
		return err
	}

	err = authSvc.repo.UpdatePassword(ctx, UpdatePasswordParams{
		UserID:         param.UserUuid,
		Password:       hashedPassword,
		LastModifiedAt: time.Now().UTC(),
	})
	if err != nil {
		slog.Error("Failed to update password", "err", err)
		return err
	}
	return nil
}
