package login

import (
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/jinzhu/copier"
	"github.com/tendant/simple-user/auth"
	"github.com/tendant/simple-user/utils"
)

const (
	ACCESS_TOKEN_NAME  = "accessToken"
	REFRESH_TOKEN_NAME = "refreshToken"
)

type Handle struct {
	loginService *LoginService
	jwtService   auth.Jwt
}

func NewHandle(loginService *LoginService, jwtService auth.Jwt) Handle {
	return Handle{
		loginService: loginService,
		jwtService:   jwtService,
	}
}

func Routes(r *chi.Mux, handle Handle) {

	r.Group(func(r chi.Router) {
		// add auth middleware
		r.Mount("/api/v4", Handler(&handle))
	})
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

// Login a user
// (POST /login)
func (h Handle) PostLogin(w http.ResponseWriter, r *http.Request) *Response {
	data := PostLoginJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "Unable to parse request body",
		}
	}

	loginParams := LoginParams{}
	copier.Copy(&loginParams, data)
	dbUsers, err := h.loginService.Login(r.Context(), loginParams)
	if err != nil || len(dbUsers) == 0 {
		slog.Error("User does not exist", "params", data, "err", err)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusUnauthorized,
		}
	}

	if len(dbUsers) > 1 {
		slog.Error("Multiple user records with same username", "username", loginParams.Username)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusUnauthorized,
		}
	}

	// FIXME: implement hashed password check
	if string(dbUsers[0].Password) != data.Password {
		slog.Error("Passwords does not match", "params", data)
		return &Response{
			body: "Username/Password is wrong",
			Code: http.StatusUnauthorized,
		}
	}

	// Find users related role
	roles, err := h.loginService.FindUserRoles(r.Context(), dbUsers[0].Uuid)
	if err != nil {
		slog.Error("failed to find user roles", "user_uuid", dbUsers[0].Uuid, "err", err)
		return &Response{
			body: "Internal error",
			Code: http.StatusInternalServerError,
		}
	}

	tokenUser := IdmUser{
		UserUuid: dbUsers[0].Uuid.String(),
		Role:     utils.GetValidStrings(roles),
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

	response := Login{
		Status:  "success",
		Message: "Login successful",
		User:    User{},
	}
	copier.Copy(&response.User, dbUsers[0])

	return PostLoginJSON200Response(response)
}

func (h Handle) PostPasswordResetInit(w http.ResponseWriter, r *http.Request) *Response {
	var body PostPasswordResetInitJSONBody

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		slog.Error("Failed extracting this email", "err", err)
		http.Error(w, "Failed extracting this email", http.StatusBadRequest)
		return nil
	}
	if body.Email != "" {
		email := body.Email
		uuid, err := h.loginService.queries.InitPassword(r.Context(), email)
		if err != nil {
			slog.Error("Failed finding user of this email", "err", err)
			http.Error(w, "Failed finding user of this email", http.StatusBadRequest)
			return nil
		}

		hash := sha256.New()
		hash.Write([]byte(uuid.String()))
		code := hash.Sum(nil)
		slog.Info("generated code", "code", code)
		return &Response{
			body:        code,
			Code:        200,
			contentType: "application/json",
		}

	} else {
		slog.Error("Email is missing in the request body", "err", err)
		http.Error(w, "Failed finding user of this email", http.StatusBadRequest)
		return nil
	}

}

func (h Handle) PostPasswordReset(w http.ResponseWriter, r *http.Request) *Response {

	data := PostPasswordResetJSONBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// FIXME: validate data.code
	slog.Info("password reset", "data", data)

	if data.Code == "" || data.Password == "" {
		slog.Error("Invalid Request.")
		return &Response{
			body: "Invalid Request.",
			Code: http.StatusBadRequest,
		}
	}

	// FIXME: hash/encode data.password, then write to database
	resetPasswordParams := PasswordReset{}
	copier.Copy(&resetPasswordParams, data)
	err = h.loginService.ResetPasswordUsers(r.Context(), resetPasswordParams)
	if err != nil {
		slog.Error("Failed updating password", "err", err)
		return &Response{
			body: "Failed updating password",
			Code: http.StatusInternalServerError,
		}
	}

	return &Response{
		Code: http.StatusOK,
	}
}

func (h Handle) GetTokenRefresh(w http.ResponseWriter, r *http.Request, params GetTokenRefreshParams) *Response {

	// FIXME: validate refreshToken
	jwt := auth.Jwt{}
	accessToken, err := jwt.CreateAccessToken("")
	if err != nil {
		slog.Error("Failed to create access token", "refresh token", params.RefreshToken, "err", err)
		return &Response{
			body: "Failed to create access token",
			Code: http.StatusInternalServerError,
		}
	}

	refreshToken, err := jwt.CreateAccessToken("")
	if err != nil {
		slog.Error("Failed to create refresh token", "refresh token", params.RefreshToken, "err", err)
		return &Response{
			body: "Failed to create refresh token",
			Code: http.StatusInternalServerError,
		}
	}

	result := Tokens{
		AccessToken:  &accessToken.Token,
		RefreshToken: &refreshToken.Token,
	}

	return &Response{
		Code: http.StatusOK,
		body: result,
	}
}

// Register a new user
// (POST /register)
func (h Handle) PostRegister(w http.ResponseWriter, r *http.Request) *Response {
	data := PostRegisterJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// FIXME:hash/encode data.password, then write to database
	registerParam := RegisterParam{}
	copier.Copy(&registerParam, data)

	_, err = h.loginService.Create(r.Context(), registerParam)
	if err != nil {
		slog.Error("Failed to register user", "email", registerParam.Email, "err", err)
		return &Response{
			body: "Failed to register user",
			Code: http.StatusInternalServerError,
		}
	}
	return &Response{
		Code: http.StatusCreated,
		body: "User registered successfully",
	}
}

// Verify email address
// (POST /email/verify)
func (h Handle) PostEmailVerify(w http.ResponseWriter, r *http.Request) *Response {
	data := PostEmailVerifyJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	email := data.Email
	err = h.loginService.EmailVerify(r.Context(), email)
	if err != nil {
		slog.Error("Failed to verify user", "email", email, "err", err)
		return &Response{
			body: "Failed to verify user",
			Code: http.StatusInternalServerError,
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: "User verified successfully",
	}
}
