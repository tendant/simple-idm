package auth

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/login"
)

type Handle struct {
	jwtService auth.Jwt
}

func NewHandle(jwtService auth.Jwt) Handle {
	return Handle{
		jwtService: jwtService,
	}
}

func (h Handle) setTokenCookie(w http.ResponseWriter, tokenName, tokenValue string, expire time.Time) {
	tokenCookie := &http.Cookie{
		Name:     tokenName,
		Path:     "/",
		Value:    tokenValue,
		Expires:  expire,
		HttpOnly: true,                 // Make the cookie HttpOnly
		Secure:   true,                 // Ensure it’s sent over HTTPS
		SameSite: http.SameSiteLaxMode, // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
}

func (h Handle) PostToken(w http.ResponseWriter, r *http.Request) *Response {
	var (
		response SuccessResponse
	)

	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	accessToken, err := h.jwtService.CreateAccessToken(authUser)
	if err != nil {
		slog.Error("Failed to create access token", "user", authUser, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(authUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "user", authUser, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	h.setTokenCookie(w, login.ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, login.REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	response.Result = "success"
	return PostTokenJSON200Response(response)
}
