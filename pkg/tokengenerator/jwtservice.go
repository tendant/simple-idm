package tokengenerator

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token type constants
const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
	TEMP_TOKEN_NAME    = "temp_token"
	LOGOUT_TOKEN_NAME  = "logout_token"
)

// Default token expiry durations
const (
	DefaultAccessTokenExpiry  = 5 * time.Minute
	DefaultRefreshTokenExpiry = 15 * time.Minute
	DefaultTempTokenExpiry    = 10 * time.Minute
	DefaultLogoutTokenExpiry  = -1 * time.Second
)

type TokenService interface {
	// Token generation methods
	GenerateTokens(subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]TokenValue, error)
	GenerateTempToken(subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]TokenValue, error)
	GenerateLogoutToken(subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]TokenValue, error)
	ParseToken(tokenStr string) (*jwt.Token, error)
}

type DefaultTokenService struct {
	accessTokenGenerator  TokenGenerator
	refreshTokenGenerator TokenGenerator
	tempTokenGenerator    TokenGenerator
	logoutTokenGenerator  TokenGenerator
	Secret                string
}

func NewDefaultTokenService(accessTokenGenerator, refreshTokenGenerator, tempTokenGenerator, logoutTokenGenerator TokenGenerator, secret string) TokenService {
	return &DefaultTokenService{
		accessTokenGenerator:  accessTokenGenerator,
		refreshTokenGenerator: refreshTokenGenerator,
		tempTokenGenerator:    tempTokenGenerator,
		logoutTokenGenerator:  logoutTokenGenerator,
		Secret:                secret,
	}
}

type TokenValue struct {
	Name   string
	Token  string
	Expiry time.Time
}

func (d *DefaultTokenService) GenerateTokens(subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]TokenValue, error) {
	tokenName := ACCESS_TOKEN_NAME
	accessToken, accessTokenExpiry, err := d.accessTokenGenerator.GenerateToken(subject, DefaultAccessTokenExpiry, rootModifications, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s token: %w", tokenName, err)
	}

	tokenName = REFRESH_TOKEN_NAME
	refreshToken, refreshTokenExpiry, err := d.refreshTokenGenerator.GenerateToken(subject, DefaultRefreshTokenExpiry, rootModifications, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s token: %w", tokenName, err)
	}

	result := map[string]TokenValue{
		ACCESS_TOKEN_NAME: {
			Name:   ACCESS_TOKEN_NAME,
			Token:  accessToken,
			Expiry: accessTokenExpiry,
		},
		REFRESH_TOKEN_NAME: {
			Name:   REFRESH_TOKEN_NAME,
			Token:  refreshToken,
			Expiry: refreshTokenExpiry,
		},
	}

	return result, nil
}

func (d *DefaultTokenService) GenerateTempToken(subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]TokenValue, error) {
	tokenName := TEMP_TOKEN_NAME
	tempToken, tempTokenExpiry, err := d.tempTokenGenerator.GenerateToken(subject, DefaultAccessTokenExpiry, rootModifications, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s token: %w", tokenName, err)
	}

	return map[string]TokenValue{
		TEMP_TOKEN_NAME: {
			Name:   TEMP_TOKEN_NAME,
			Token:  tempToken,
			Expiry: tempTokenExpiry,
		},
	}, nil
}

func (d *DefaultTokenService) GenerateLogoutToken(subject string, rootModifications map[string]interface{}, extraClaims map[string]interface{}) (map[string]TokenValue, error) {
	tokenName := LOGOUT_TOKEN_NAME
	logoutToken, logoutTokenExpiry, err := d.logoutTokenGenerator.GenerateToken(subject, DefaultAccessTokenExpiry, rootModifications, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s token: %w", tokenName, err)
	}

	return map[string]TokenValue{
		LOGOUT_TOKEN_NAME: {
			Name:   LOGOUT_TOKEN_NAME,
			Token:  logoutToken,
			Expiry: logoutTokenExpiry,
		},
	}, nil
}

func (d *DefaultTokenService) ParseToken(tokenStr string) (*jwt.Token, error) {
	signingKey := []byte(d.Secret)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		slog.Error("Failed parse JWT string!", "err", err)
		return token, err
	}

	// Since we don't have a LoadFromMap function or Claims struct defined,
	// we'll just return the token if it's valid
	if token.Valid {
		return token, nil
	}

	slog.Error("Failed parse token claims!", "err", "token invalid")
	return token, fmt.Errorf("failed_parse_token_claims")
}

type TokenCookieService interface {
	SetTokensCookie(w http.ResponseWriter, tokens map[string]TokenValue) error
	ClearCookies(w http.ResponseWriter) error
}

type DefaultTokenCookieService struct {
	Path     string
	HttpOnly bool
	Secure   bool
	SameSite http.SameSite
}

func (d *DefaultTokenCookieService) SetTokensCookie(w http.ResponseWriter, tokens map[string]TokenValue) error {
	for name, token := range tokens {
		cookie := &http.Cookie{
			Name:     name,
			Path:     d.Path,
			Value:    token.Token,
			Expires:  token.Expiry,
			HttpOnly: d.HttpOnly,
			Secure:   d.Secure,
			SameSite: d.SameSite,
		}

		http.SetCookie(w, cookie)
	}
	return nil
}

func (d *DefaultTokenCookieService) ClearCookies(w http.ResponseWriter) error {
	for _, name := range []string{ACCESS_TOKEN_NAME, REFRESH_TOKEN_NAME, TEMP_TOKEN_NAME} {
		cookie := &http.Cookie{
			Name:   name,
			Path:   d.Path,
			Value:  "",
			MaxAge: -1,
		}
		http.SetCookie(w, cookie)
	}
	return nil
}

func NewDefaultTokenCookieService(path string, httpOnly, secure bool, sameSite http.SameSite) TokenCookieService {
	return &DefaultTokenCookieService{
		Path:     path,
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: sameSite,
	}
}
