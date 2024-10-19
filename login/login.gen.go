// Package login provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/discord-gophers/goapi-gen version v0.3.0 DO NOT EDIT.
package login

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/discord-gophers/goapi-gen/runtime"
	openapi_types "github.com/discord-gophers/goapi-gen/types"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// EmailVerifyRequest defines model for EmailVerifyRequest.
type EmailVerifyRequest struct {
	Email string `json:"email"`
}

// Login defines model for Login.
type Login struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	User    User   `json:"user"`
}

// PasswordReset defines model for PasswordReset.
type PasswordReset struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

// PasswordResetInit defines model for PasswordResetInit.
type PasswordResetInit struct {
	Email string `json:"email"`
}

// RegisterRequest defines model for RegisterRequest.
type RegisterRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Tokens defines model for Tokens.
type Tokens struct {
	AccessToken  *string `json:"accessToken,omitempty"`
	RefreshToken *string `json:"refreshToken,omitempty"`
}

// User defines model for User.
type User struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
}

// PostEmailVerifyJSONBody defines parameters for PostEmailVerify.
type PostEmailVerifyJSONBody EmailVerifyRequest

// PostLoginJSONBody defines parameters for PostLogin.
type PostLoginJSONBody struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// PostPasswordResetJSONBody defines parameters for PostPasswordReset.
type PostPasswordResetJSONBody PasswordReset

// PostPasswordResetInitJSONBody defines parameters for PostPasswordResetInit.
type PostPasswordResetInitJSONBody PasswordResetInit

// PostRegisterJSONBody defines parameters for PostRegister.
type PostRegisterJSONBody RegisterRequest

// GetTokenRefreshParams defines parameters for GetTokenRefresh.
type GetTokenRefreshParams struct {
	RefreshToken string `json:"refreshToken"`
}

// PostEmailVerifyJSONRequestBody defines body for PostEmailVerify for application/json ContentType.
type PostEmailVerifyJSONRequestBody PostEmailVerifyJSONBody

// Bind implements render.Binder.
func (PostEmailVerifyJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// PostLoginJSONRequestBody defines body for PostLogin for application/json ContentType.
type PostLoginJSONRequestBody PostLoginJSONBody

// Bind implements render.Binder.
func (PostLoginJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// PostPasswordResetJSONRequestBody defines body for PostPasswordReset for application/json ContentType.
type PostPasswordResetJSONRequestBody PostPasswordResetJSONBody

// Bind implements render.Binder.
func (PostPasswordResetJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// PostPasswordResetInitJSONRequestBody defines body for PostPasswordResetInit for application/json ContentType.
type PostPasswordResetInitJSONRequestBody PostPasswordResetInitJSONBody

// Bind implements render.Binder.
func (PostPasswordResetInitJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// PostRegisterJSONRequestBody defines body for PostRegister for application/json ContentType.
type PostRegisterJSONRequestBody PostRegisterJSONBody

// Bind implements render.Binder.
func (PostRegisterJSONRequestBody) Bind(*http.Request) error {
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

// PostEmailVerifyJSON200Response is a constructor method for a PostEmailVerify response.
// A *Response is returned with the configured status code and content type from the spec.
func PostEmailVerifyJSON200Response(body struct {
	Message *string `json:"message,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// PostLoginJSON200Response is a constructor method for a PostLogin response.
// A *Response is returned with the configured status code and content type from the spec.
func PostLoginJSON200Response(body Login) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// PostPasswordResetJSON200Response is a constructor method for a PostPasswordReset response.
// A *Response is returned with the configured status code and content type from the spec.
func PostPasswordResetJSON200Response(body struct {
	Message *string `json:"message,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// PostPasswordResetInitJSON200Response is a constructor method for a PostPasswordResetInit response.
// A *Response is returned with the configured status code and content type from the spec.
func PostPasswordResetInitJSON200Response(body struct {
	Message *string `json:"message,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// PostRegisterJSON201Response is a constructor method for a PostRegister response.
// A *Response is returned with the configured status code and content type from the spec.
func PostRegisterJSON201Response(body struct {
	Email *openapi_types.Email `json:"email,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        201,
		contentType: "application/json",
	}
}

// GetTokenRefreshJSON200Response is a constructor method for a GetTokenRefresh response.
// A *Response is returned with the configured status code and content type from the spec.
func GetTokenRefreshJSON200Response(body Tokens) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Verify email address
	// (POST /email/verify)
	PostEmailVerify(w http.ResponseWriter, r *http.Request) *Response
	// Login a user
	// (POST /login)
	PostLogin(w http.ResponseWriter, r *http.Request) *Response
	// Reset password
	// (POST /password/reset)
	PostPasswordReset(w http.ResponseWriter, r *http.Request) *Response
	// Initiate password reset
	// (POST /password/reset:init)
	PostPasswordResetInit(w http.ResponseWriter, r *http.Request) *Response
	// Register a new user
	// (POST /register)
	PostRegister(w http.ResponseWriter, r *http.Request) *Response
	// Refresh JWT tokens
	// (GET /token/refresh)
	GetTokenRefresh(w http.ResponseWriter, r *http.Request, params GetTokenRefreshParams) *Response
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler          ServerInterface
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// PostEmailVerify operation middleware
func (siw *ServerInterfaceWrapper) PostEmailVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.PostEmailVerify(w, r)
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

// PostLogin operation middleware
func (siw *ServerInterfaceWrapper) PostLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.PostLogin(w, r)
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

// PostPasswordReset operation middleware
func (siw *ServerInterfaceWrapper) PostPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.PostPasswordReset(w, r)
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

// PostPasswordResetInit operation middleware
func (siw *ServerInterfaceWrapper) PostPasswordResetInit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.PostPasswordResetInit(w, r)
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

// PostRegister operation middleware
func (siw *ServerInterfaceWrapper) PostRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.PostRegister(w, r)
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

// GetTokenRefresh operation middleware
func (siw *ServerInterfaceWrapper) GetTokenRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parameter object where we will unmarshal all parameters from the context
	var params GetTokenRefreshParams

	// ------------- Required query parameter "refreshToken" -------------

	if err := runtime.BindQueryParameter("form", true, true, "refreshToken", r.URL.Query(), &params.RefreshToken); err != nil {
		err = fmt.Errorf("invalid format for parameter refreshToken: %w", err)
		siw.ErrorHandlerFunc(w, r, &RequiredParamError{err, "refreshToken"})
		return
	}

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.GetTokenRefresh(w, r, params)
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
		r.Post("/email/verify", wrapper.PostEmailVerify)
		r.Post("/login", wrapper.PostLogin)
		r.Post("/password/reset", wrapper.PostPasswordReset)
		r.Post("/password/reset:init", wrapper.PostPasswordResetInit)
		r.Post("/register", wrapper.PostRegister)
		r.Get("/token/refresh", wrapper.GetTokenRefresh)
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

	"H4sIAAAAAAAC/8xWQW/bPAz9KwK/72jE6XbzaRs2DC02oAja7VAUhWYzibpYciW5XRD4vw+iZCdOFCfr",
	"mmI3QyYpvvcokivIVVkpidIayFZg8jmWnD4/lVwsvqEW0+UEH2o01p1WWlWorUCyQWfjPuyyQsjAWC3k",
	"DJomAY0PtdBYQHYTzG6T1kz9uMfcQpPAFzUTcjduicbwGUYiJ2Ast7W//RcvqwX9rfMcjYFk17w2qJ3x",
	"/xqnkMF/6RpwGtCm185mO+lwT9IlE2LFYFxyY56ULiZoMEJTroo4lir4HaaQQmw4HMziXIpTCDbBmTAW",
	"9eGSWKtzr+ZyVCh8F45GuSpjUkleYt/zQs0l+6gwZn08dxQ3CZkd4PBK/URpdmFxKjD6G1VS41Sjme8z",
	"aCJXXYfKPE6hNT27JV6LI1ggq6RPxi4DzkvIqaJ4wpIKLlH2lUs+wxKlZe8vzyGBR9RGKAkZnI3Go7FL",
	"RFUoeSUgg7d05Li2c4KV0oXpI/UTQq189Tjs3AolzwvI4FIZu9F4wENAYz+oYumfkrQoyZNX1ULk5Jve",
	"GyXX/evQe4+0tqZPl9U10oGplDRemTfj8R9lcGxLa6IiFGhyLSrrKaaMGbEnsGCh303rxWJJAUxdllwv",
	"IQMPixHdjBeFdn3RmaSLrtfupd634+eT3oc88EJ9L91T0duF21oOPt2X12+ogjxREaHorRDTQyKRO+Os",
	"bgdP2iJLdTdC9qrUnzaneSL9O/7x19Emy4i8IeIJDuvKKEJ9JtrBeRz/NGdfQQO65zV1WE9hqmkdBv92",
	"90leQDDfrIzLty+XAy24xU4x7+B1azMaFqtdWE6k0fY+dJRCZ3+hULcfTJUuuYWs22ueoQMpm2vkdnio",
	"tCgZZxKfNtqWdftOGpYfl9UMIzp8RkuL0STYuUaueYkWtYHsZgVuLsFDjXrZbihZf6Pa5jTZ4Gdj0Xyy",
	"d8Htzga/bVZuTzgVwvIYIdr/YSG5Q2STEbv4fsVsF7H5HQAA///uvJLgqw0AAA==",
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
