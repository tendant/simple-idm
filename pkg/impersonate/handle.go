package impersonate

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/auth"
	"github.com/tendant/simple-idm/pkg/login"
	"github.com/tendant/simple-idm/pkg/utils"
)

const (
	ACCESS_TOKEN_NAME  = "access_token"
	REFRESH_TOKEN_NAME = "refresh_token"
)

type Handle struct {
	impersonateService *ImpersonateService
	jwtService         auth.Jwt
}

type Impersonnate struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	User    ImpersonateUser
}

type ImpersonateUser struct {
	UserUuid      string   `json:"user_uuid,omitempty"`
	DelegateeUuid string   `json:"delegatee_uuid,omitempty"`
	Role          []string `json:"role,omitempty"`
}

func NewHandle(impersonateService *ImpersonateService, jwtService auth.Jwt) Handle {
	return Handle{
		impersonateService: impersonateService,
		jwtService:         jwtService,
	}
}

func (h Handle) setTokenCookie(w http.ResponseWriter, tokenName, tokenValue string, expire time.Time) {
	tokenCookie := &http.Cookie{
		Name:     tokenName,
		Path:     "/",
		Value:    tokenValue,
		Expires:  expire,
		HttpOnly: h.jwtService.CoookieHttpOnly, // Make the cookie HttpOnly
		Secure:   h.jwtService.CookieSecure,    // Ensure it’s sent over HTTPS
		SameSite: http.SameSiteLaxMode,         // Prevent CSRF
	}

	http.SetCookie(w, tokenCookie)
}

// Impersonate a user
// (POST /impersonate)
func (h Handle) CreateImpersonate(w http.ResponseWriter, r *http.Request) *Response {
	authUser, ok := r.Context().Value(login.AuthUserKey).(*login.AuthUser)
	if !ok {
		slog.Error("Failed getting AuthUser", "ok", ok)
		return &Response{
			body: http.StatusText(http.StatusUnauthorized),
			Code: http.StatusUnauthorized,
		}
	}

	// Get user UUID from context (assuming it's set by auth middleware)
	delegatee_uuid := authUser.UserUuid

	data := CreateImpersonateJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	delegatorUserUuid, err := uuid.Parse(data.UserUUID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid user UUID format",
		}
	}

	// TODO: validate delegator and delegatee relationship

	delegatorRoles, err := h.impersonateService.FindDelegatorRoles(r.Context(), delegatorUserUuid)
	if err != nil {
		slog.Error("Failed to find delegator roles", "delegatorUserUuid", delegatorUserUuid, "err", err)
		return &Response{
			Code: http.StatusInternalServerError,
			body: "Failed to find delegator roles",
		}
	}

	tokenUser := ImpersonateUser{
		UserUuid:      delegatorUserUuid.String(),
		Role:          utils.GetValidStrings(delegatorRoles),
		DelegateeUuid: delegatee_uuid.String(),
	}

	accessToken, err := h.jwtService.CreateAccessToken(tokenUser)
	if err != nil {
		slog.Error("Failed to create access token", "user", tokenUser, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := h.jwtService.CreateRefreshToken(tokenUser)
	if err != nil {
		slog.Error("Failed to create refresh token", "user", tokenUser, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	h.setTokenCookie(w, ACCESS_TOKEN_NAME, accessToken.Token, accessToken.Expiry)
	h.setTokenCookie(w, REFRESH_TOKEN_NAME, refreshToken.Token, refreshToken.Expiry)

	return &Response{
		body: Impersonnate{
			Message: "Impersonation successful",
			Status:  "success",
			User: ImpersonateUser{
				UserUuid:      tokenUser.UserUuid,
				Role:          tokenUser.Role,
				DelegateeUuid: tokenUser.DelegateeUuid,
			},
		},
		Code: http.StatusOK,
	}
}
