// Package api provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/discord-gophers/goapi-gen version v0.3.0 DO NOT EDIT.
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const (
	BearerAuthScopes = "bearerAuth.Scopes"
)

// Error defines model for Error.
type Error struct {
	// Error code
	Code string `json:"code"`

	// Error message
	Message string `json:"message"`
}

// Login defines model for Login.
type Login struct {
	// Token for 2FA verification if required
	LoginToken *string `json:"loginToken,omitempty"`
	Message    string  `json:"message"`

	// Whether 2FA verification is required
	Requires2fA *bool  `json:"requires2FA,omitempty"`
	Status      string `json:"status"`
	User        User   `json:"user"`

	// List of users associated with the login. Usually contains one user, but may contain multiple if same username is shared.
	Users []User `json:"users,omitempty"`
}

// MultiUsersResponse defines model for MultiUsersResponse.
type MultiUsersResponse struct {
	Users []User `json:"users,omitempty"`
}

// PasswordPolicyResponse defines model for PasswordPolicyResponse.
type PasswordPolicyResponse struct {
	// Whether common passwords are disallowed
	DisallowCommonPwds *bool `json:"disallow_common_pwds,omitempty"`

	// Number of days until password expires
	ExpirationDays *int `json:"expiration_days,omitempty"`

	// Number of previous passwords to check against
	HistoryCheckCount *int `json:"history_check_count,omitempty"`

	// Maximum number of repeated characters allowed
	MaxRepeatedChars *int `json:"max_repeated_chars,omitempty"`

	// Minimum length of the password
	MinLength *int `json:"min_length,omitempty"`

	// Whether the password requires a digit
	RequireDigit *bool `json:"require_digit,omitempty"`

	// Whether the password requires a lowercase letter
	RequireLowercase *bool `json:"require_lowercase,omitempty"`

	// Whether the password requires a special character
	RequireSpecialChar *bool `json:"require_special_char,omitempty"`

	// Whether the password requires an uppercase letter
	RequireUppercase *bool `json:"require_uppercase,omitempty"`
}

// Structure added for integration compatibility purposes
type SingleUserResponse struct {
	User User `json:"user,omitempty"`
}

// SuccessResponse defines model for SuccessResponse.
type SuccessResponse struct {
	Result string `json:"result,omitempty"`
}

// TwoFactorMethod defines model for TwoFactorMethod.
type TwoFactorMethod struct {
	Enabled     bool   `json:"enabled"`
	TwoFactorID string `json:"two_factor_id,omitempty"`
	Type        string `json:"type"`
}

// TwoFactorMethods defines model for TwoFactorMethods.
type TwoFactorMethods struct {
	Count   int               `json:"count"`
	Methods []TwoFactorMethod `json:"methods"`
}

// User defines model for User.
type User struct {
	Email string `json:"email"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// Delete2faJSONBody defines parameters for Delete2fa.
type Delete2faJSONBody struct {
	TwofaID   *string                    `json:"twofa_id,omitempty"`
	TwofaType Delete2faJSONBodyTwofaType `json:"twofa_type"`
}

// Delete2faJSONBodyTwofaType defines parameters for Delete2fa.
type Delete2faJSONBodyTwofaType string

// Post2faDisableJSONBody defines parameters for Post2faDisable.
type Post2faDisableJSONBody struct {
	TwofaType Post2faDisableJSONBodyTwofaType `json:"twofa_type"`
}

// Post2faDisableJSONBodyTwofaType defines parameters for Post2faDisable.
type Post2faDisableJSONBodyTwofaType string

// Post2faEnableJSONBody defines parameters for Post2faEnable.
type Post2faEnableJSONBody struct {
	TwofaType Post2faEnableJSONBodyTwofaType `json:"twofa_type"`
}

// Post2faEnableJSONBodyTwofaType defines parameters for Post2faEnable.
type Post2faEnableJSONBodyTwofaType string

// Post2faSetupJSONBody defines parameters for Post2faSetup.
type Post2faSetupJSONBody struct {
	TwofaType Post2faSetupJSONBodyTwofaType `json:"twofa_type"`
}

// Post2faSetupJSONBodyTwofaType defines parameters for Post2faSetup.
type Post2faSetupJSONBodyTwofaType string

// AssociateLoginJSONBody defines parameters for AssociateLogin.
type AssociateLoginJSONBody struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// ChangePasswordJSONBody defines parameters for ChangePassword.
type ChangePasswordJSONBody struct {
	// User's current password
	CurrentPassword string `json:"current_password"`

	// User's new password
	NewPassword string `json:"new_password"`
}

// PostUserSwitchJSONBody defines parameters for PostUserSwitch.
type PostUserSwitchJSONBody struct {
	// ID of the user to switch to
	UserID string `json:"user_id"`
}

// ChangeUsernameJSONBody defines parameters for ChangeUsername.
type ChangeUsernameJSONBody struct {
	// User's current password for verification
	CurrentPassword string `json:"currentPassword"`

	// New username to set
	NewUsername string `json:"newUsername"`
}

// Delete2faJSONRequestBody defines body for Delete2fa for application/json ContentType.
type Delete2faJSONRequestBody Delete2faJSONBody

// Bind implements render.Binder.
func (Delete2faJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// Post2faDisableJSONRequestBody defines body for Post2faDisable for application/json ContentType.
type Post2faDisableJSONRequestBody Post2faDisableJSONBody

// Bind implements render.Binder.
func (Post2faDisableJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// Post2faEnableJSONRequestBody defines body for Post2faEnable for application/json ContentType.
type Post2faEnableJSONRequestBody Post2faEnableJSONBody

// Bind implements render.Binder.
func (Post2faEnableJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// Post2faSetupJSONRequestBody defines body for Post2faSetup for application/json ContentType.
type Post2faSetupJSONRequestBody Post2faSetupJSONBody

// Bind implements render.Binder.
func (Post2faSetupJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// AssociateLoginJSONRequestBody defines body for AssociateLogin for application/json ContentType.
type AssociateLoginJSONRequestBody AssociateLoginJSONBody

// Bind implements render.Binder.
func (AssociateLoginJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// ChangePasswordJSONRequestBody defines body for ChangePassword for application/json ContentType.
type ChangePasswordJSONRequestBody ChangePasswordJSONBody

// Bind implements render.Binder.
func (ChangePasswordJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// PostUserSwitchJSONRequestBody defines body for PostUserSwitch for application/json ContentType.
type PostUserSwitchJSONRequestBody PostUserSwitchJSONBody

// Bind implements render.Binder.
func (PostUserSwitchJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// ChangeUsernameJSONRequestBody defines body for ChangeUsername for application/json ContentType.
type ChangeUsernameJSONRequestBody ChangeUsernameJSONBody

// Bind implements render.Binder.
func (ChangeUsernameJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// Response is a common response struct for all the API calls.
// A Response object may be instantiated via functions for specific operation responses.
// It may also be instantiated directly, for the purpose of responding with a single status code.
type Response struct {
	body        interface{}
	Code        int
	contentType string
}

// Render implements the render.Renderer interface. It sets the Content-Type header
// and status code based on the response definition.
func (resp *Response) Render(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", resp.contentType)
	render.Status(r, resp.Code)
	return nil
}

// Status is a builder method to override the default status code for a response.
func (resp *Response) Status(code int) *Response {
	resp.Code = code
	return resp
}

// ContentType is a builder method to override the default content type for a response.
func (resp *Response) ContentType(contentType string) *Response {
	resp.contentType = contentType
	return resp
}

// MarshalJSON implements the json.Marshaler interface.
// This is used to only marshal the body of the response.
func (resp *Response) MarshalJSON() ([]byte, error) {
	return json.Marshal(resp.body)
}

// MarshalXML implements the xml.Marshaler interface.
// This is used to only marshal the body of the response.
func (resp *Response) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.Encode(resp.body)
}

// Get2faMethodsJSON200Response is a constructor method for a Get2faMethods response.
// A *Response is returned with the configured status code and content type from the spec.
func Get2faMethodsJSON200Response(body TwoFactorMethods) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// Get2faMethodsJSON404Response is a constructor method for a Get2faMethods response.
// A *Response is returned with the configured status code and content type from the spec.
func Get2faMethodsJSON404Response(body struct {
	Message *string `json:"message,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        404,
		contentType: "application/json",
	}
}

// Delete2faJSON200Response is a constructor method for a Delete2fa response.
// A *Response is returned with the configured status code and content type from the spec.
func Delete2faJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// Post2faDisableJSON200Response is a constructor method for a Post2faDisable response.
// A *Response is returned with the configured status code and content type from the spec.
func Post2faDisableJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// Post2faEnableJSON200Response is a constructor method for a Post2faEnable response.
// A *Response is returned with the configured status code and content type from the spec.
func Post2faEnableJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// Post2faSetupJSON201Response is a constructor method for a Post2faSetup response.
// A *Response is returned with the configured status code and content type from the spec.
func Post2faSetupJSON201Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        201,
		contentType: "application/json",
	}
}

// AssociateLoginJSON200Response is a constructor method for a AssociateLogin response.
// A *Response is returned with the configured status code and content type from the spec.
func AssociateLoginJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// ChangePasswordJSON400Response is a constructor method for a ChangePassword response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangePasswordJSON400Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        400,
		contentType: "application/json",
	}
}

// ChangePasswordJSON401Response is a constructor method for a ChangePassword response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangePasswordJSON401Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        401,
		contentType: "application/json",
	}
}

// ChangePasswordJSON403Response is a constructor method for a ChangePassword response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangePasswordJSON403Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        403,
		contentType: "application/json",
	}
}

// ChangePasswordJSON500Response is a constructor method for a ChangePassword response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangePasswordJSON500Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        500,
		contentType: "application/json",
	}
}

// GetPasswordPolicyJSON200Response is a constructor method for a GetPasswordPolicy response.
// A *Response is returned with the configured status code and content type from the spec.
func GetPasswordPolicyJSON200Response(body PasswordPolicyResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// PostUserSwitchJSON200Response is a constructor method for a PostUserSwitch response.
// A *Response is returned with the configured status code and content type from the spec.
func PostUserSwitchJSON200Response(body interface{}) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// PostUserSwitchJSON400Response is a constructor method for a PostUserSwitch response.
// A *Response is returned with the configured status code and content type from the spec.
func PostUserSwitchJSON400Response(body struct {
	Message *string `json:"message,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        400,
		contentType: "application/json",
	}
}

// PostUserSwitchJSON403Response is a constructor method for a PostUserSwitch response.
// A *Response is returned with the configured status code and content type from the spec.
func PostUserSwitchJSON403Response(body struct {
	Message *string `json:"message,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        403,
		contentType: "application/json",
	}
}

// ChangeUsernameJSON400Response is a constructor method for a ChangeUsername response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangeUsernameJSON400Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        400,
		contentType: "application/json",
	}
}

// ChangeUsernameJSON401Response is a constructor method for a ChangeUsername response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangeUsernameJSON401Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        401,
		contentType: "application/json",
	}
}

// ChangeUsernameJSON403Response is a constructor method for a ChangeUsername response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangeUsernameJSON403Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        403,
		contentType: "application/json",
	}
}

// ChangeUsernameJSON409Response is a constructor method for a ChangeUsername response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangeUsernameJSON409Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        409,
		contentType: "application/json",
	}
}

// ChangeUsernameJSON500Response is a constructor method for a ChangeUsername response.
// A *Response is returned with the configured status code and content type from the spec.
func ChangeUsernameJSON500Response(body Error) *Response {
	return &Response{
		body:        body,
		Code:        500,
		contentType: "application/json",
	}
}

// FindUsersWithLoginJSON200Response is a constructor method for a FindUsersWithLogin response.
// A *Response is returned with the configured status code and content type from the spec.
func FindUsersWithLoginJSON200Response(body interface{}) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Get login 2FA methods
	// (GET /2fa)
	Get2faMethods(w http.ResponseWriter, r *http.Request) *Response
	// Delete a 2FA method
	// (POST /2fa/delete)
	Delete2fa(w http.ResponseWriter, r *http.Request) *Response
	// Disable an existing 2FA method
	// (POST /2fa/disable)
	Post2faDisable(w http.ResponseWriter, r *http.Request) *Response
	// Enable an existing 2FA method
	// (POST /2fa/enable)
	Post2faEnable(w http.ResponseWriter, r *http.Request) *Response
	// Create a new 2FA method
	// (POST /2fa/setup)
	Post2faSetup(w http.ResponseWriter, r *http.Request) *Response
	// Associate a login
	// (POST /login/associate)
	AssociateLogin(w http.ResponseWriter, r *http.Request) *Response
	// Change user password
	// (PUT /password)
	ChangePassword(w http.ResponseWriter, r *http.Request) *Response
	// Get password policy
	// (GET /password/policy)
	GetPasswordPolicy(w http.ResponseWriter, r *http.Request) *Response
	// Switch to a different user when multiple users are available for the same login
	// (POST /user/switch)
	PostUserSwitch(w http.ResponseWriter, r *http.Request) *Response
	// Change username
	// (PUT /username)
	ChangeUsername(w http.ResponseWriter, r *http.Request) *Response
	// Get a list of users associated with the current login
	// (GET /users)
	FindUsersWithLogin(w http.ResponseWriter, r *http.Request) *Response
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler          ServerInterface
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// Get2faMethods operation middleware
func (siw *ServerInterfaceWrapper) Get2faMethods(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Get2faMethods(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// Delete2fa operation middleware
func (siw *ServerInterfaceWrapper) Delete2fa(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Delete2fa(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// Post2faDisable operation middleware
func (siw *ServerInterfaceWrapper) Post2faDisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Post2faDisable(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// Post2faEnable operation middleware
func (siw *ServerInterfaceWrapper) Post2faEnable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Post2faEnable(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// Post2faSetup operation middleware
func (siw *ServerInterfaceWrapper) Post2faSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Post2faSetup(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// AssociateLogin operation middleware
func (siw *ServerInterfaceWrapper) AssociateLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.AssociateLogin(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// ChangePassword operation middleware
func (siw *ServerInterfaceWrapper) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ctx = context.WithValue(ctx, BearerAuthScopes, []string{""})

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.ChangePassword(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// GetPasswordPolicy operation middleware
func (siw *ServerInterfaceWrapper) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.GetPasswordPolicy(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// PostUserSwitch operation middleware
func (siw *ServerInterfaceWrapper) PostUserSwitch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.PostUserSwitch(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// ChangeUsername operation middleware
func (siw *ServerInterfaceWrapper) ChangeUsername(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ctx = context.WithValue(ctx, BearerAuthScopes, []string{""})

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.ChangeUsername(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

// FindUsersWithLogin operation middleware
func (siw *ServerInterfaceWrapper) FindUsersWithLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.FindUsersWithLogin(w, r)
		if resp != nil {
			if resp.body != nil {
				render.Render(w, r, resp)
			} else {
				w.WriteHeader(resp.Code)
			}
		}
	})

	handler(w, r.WithContext(ctx))
}

type UnescapedCookieParamError struct {
	err       error
	paramName string
}

// Error implements error.
func (err UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter %s: %v", err.paramName, err.err)
}

func (err UnescapedCookieParamError) Unwrap() error { return err.err }

type UnmarshalingParamError struct {
	err       error
	paramName string
}

// Error implements error.
func (err UnmarshalingParamError) Error() string {
	return fmt.Sprintf("error unmarshaling parameter %s as JSON: %v", err.paramName, err.err)
}

func (err UnmarshalingParamError) Unwrap() error { return err.err }

type RequiredParamError struct {
	err       error
	paramName string
}

// Error implements error.
func (err RequiredParamError) Error() string {
	if err.err == nil {
		return fmt.Sprintf("query parameter %s is required, but not found", err.paramName)
	} else {
		return fmt.Sprintf("query parameter %s is required, but errored: %s", err.paramName, err.err)
	}
}

func (err RequiredParamError) Unwrap() error { return err.err }

type RequiredHeaderError struct {
	paramName string
}

// Error implements error.
func (err RequiredHeaderError) Error() string {
	return fmt.Sprintf("header parameter %s is required, but not found", err.paramName)
}

type InvalidParamFormatError struct {
	err       error
	paramName string
}

// Error implements error.
func (err InvalidParamFormatError) Error() string {
	return fmt.Sprintf("invalid format for parameter %s: %v", err.paramName, err.err)
}

func (err InvalidParamFormatError) Unwrap() error { return err.err }

type TooManyValuesForParamError struct {
	NumValues int
	paramName string
}

// Error implements error.
func (err TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("expected one value for %s, got %d", err.paramName, err.NumValues)
}

// ParameterName is an interface that is implemented by error types that are
// relevant to a specific parameter.
type ParameterError interface {
	error
	// ParamName is the name of the parameter that the error is referring to.
	ParamName() string
}

func (err UnescapedCookieParamError) ParamName() string  { return err.paramName }
func (err UnmarshalingParamError) ParamName() string     { return err.paramName }
func (err RequiredParamError) ParamName() string         { return err.paramName }
func (err RequiredHeaderError) ParamName() string        { return err.paramName }
func (err InvalidParamFormatError) ParamName() string    { return err.paramName }
func (err TooManyValuesForParamError) ParamName() string { return err.paramName }

type ServerOptions struct {
	BaseURL          string
	BaseRouter       chi.Router
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

type ServerOption func(*ServerOptions)

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface, opts ...ServerOption) http.Handler {
	options := &ServerOptions{
		BaseURL:    "/",
		BaseRouter: chi.NewRouter(),
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		},
	}

	for _, f := range opts {
		f(options)
	}

	r := options.BaseRouter
	wrapper := ServerInterfaceWrapper{
		Handler:          si,
		ErrorHandlerFunc: options.ErrorHandlerFunc,
	}

	r.Route(options.BaseURL, func(r chi.Router) {
		r.Get("/2fa", wrapper.Get2faMethods)
		r.Post("/2fa/delete", wrapper.Delete2fa)
		r.Post("/2fa/disable", wrapper.Post2faDisable)
		r.Post("/2fa/enable", wrapper.Post2faEnable)
		r.Post("/2fa/setup", wrapper.Post2faSetup)
		r.Post("/login/associate", wrapper.AssociateLogin)
		r.Put("/password", wrapper.ChangePassword)
		r.Get("/password/policy", wrapper.GetPasswordPolicy)
		r.Post("/user/switch", wrapper.PostUserSwitch)
		r.Put("/username", wrapper.ChangeUsername)
		r.Get("/users", wrapper.FindUsersWithLogin)
	})
	return r
}

func WithRouter(r chi.Router) ServerOption {
	return func(s *ServerOptions) {
		s.BaseRouter = r
	}
}

func WithServerBaseURL(url string) ServerOption {
	return func(s *ServerOptions) {
		s.BaseURL = url
	}
}

func WithErrorHandler(handler func(w http.ResponseWriter, r *http.Request, err error)) ServerOption {
	return func(s *ServerOptions) {
		s.ErrorHandlerFunc = handler
	}
}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"//8r6aUHpygAAA==",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
