package auth

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tendant/simple-idm/pkg/auth/db"
	"github.com/tendant/simple-idm/pkg/login"
	"golang.org/x/crypto/bcrypt"
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
		RequiredNonAlphanumeric bool
		RequiredUppercase       bool
		RequiredLength          int
	}

	AuthLoginService struct {
		queries    *db.Queries
		pwdComplex PasswordComplexity
	}
)

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
	loginRecord, err := authSvc.queries.FindUserByUserUuid(ctx, param.UserUuid)
	if err == pgx.ErrNoRows {
		slog.Error("No user record found", "user uuid", param.UserUuid, "err", err)
		return false, nil
	} else if err != nil {
		slog.Error("Failed to find user record", "user uuid", param.UserUuid, "err", err)
		return false, err
	}
	return login.CheckPasswordHash(param.Password, loginRecord.Password.String)
}

func (authSvc AuthLoginService) UpdatePassword(ctx context.Context, param UpdatePassParam) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(param.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("Failed to generate password hash", "err", err)
		return err
	}
	err = authSvc.queries.UpdatePassowrd(ctx, db.UpdatePassowrdParams{
		Password:       sql.NullString{Valid: true, String: string(hash)},
		LastModifiedAt: time.Now().UTC(),
		Uuid:           param.UserUuid,
	})
	if err != nil {
		slog.Error("Failed to update password", "user uuid", param.UserUuid, "err", err)
		return err
	}
	return nil
}
