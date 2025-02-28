// Package twofa provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/discord-gophers/goapi-gen version v0.3.0 DO NOT EDIT.
package twofa

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
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// SuccessResponse defines model for SuccessResponse.
type SuccessResponse struct {
	Result string `json:"result,omitempty"`
}

// Post2faValidateJSONBody defines parameters for Post2faValidate.
type Post2faValidateJSONBody struct {
	LoginID   string `json:"login_id"`
	Passcode  string `json:"passcode"`
	TwofaType string `json:"twofa_type"`
}

// Post2faSendJSONBody defines parameters for Post2faSend.
type Post2faSendJSONBody struct {
	Email     string `json:"email"`
	LoginID   string `json:"login_id"`
	TwofaType string `json:"twofa_type"`
}

// Post2faValidateJSONRequestBody defines body for Post2faValidate for application/json ContentType.
type Post2faValidateJSONRequestBody Post2faValidateJSONBody

// Bind implements render.Binder.
func (Post2faValidateJSONRequestBody) Bind(*http.Request) error {
	return nil
}

// Post2faSendJSONRequestBody defines body for Post2faSend for application/json ContentType.
type Post2faSendJSONRequestBody Post2faSendJSONBody

// Bind implements render.Binder.
func (Post2faSendJSONRequestBody) Bind(*http.Request) error {
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

// Post2faValidateJSON200Response is a constructor method for a Post2faValidate response.
// A *Response is returned with the configured status code and content type from the spec.
func Post2faValidateJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// Post2faSendJSON200Response is a constructor method for a Post2faSend response.
// A *Response is returned with the configured status code and content type from the spec.
func Post2faSendJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// Get2faEnabledJSON200Response is a constructor method for a Get2faEnabled response.
// A *Response is returned with the configured status code and content type from the spec.
func Get2faEnabledJSON200Response(body struct {
	N2faMethods []string `json:"2fa_methods,omitempty"`
}) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Authenticate 2fa passcode
	// (POST /2fa)
	Post2faValidate(w http.ResponseWriter, r *http.Request) *Response
	// Initiate sending 2fa code
	// (POST /2fa/send)
	Post2faSend(w http.ResponseWriter, r *http.Request) *Response
	// Get all enabled 2fas
	// (GET /{login_id}/2fa/enabled)
	Get2faEnabled(w http.ResponseWriter, r *http.Request, loginID string) *Response
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler          ServerInterface
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// Post2faValidate operation middleware
func (siw *ServerInterfaceWrapper) Post2faValidate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Post2faValidate(w, r)
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

// Post2faSend operation middleware
func (siw *ServerInterfaceWrapper) Post2faSend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Post2faSend(w, r)
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

// Get2faEnabled operation middleware
func (siw *ServerInterfaceWrapper) Get2faEnabled(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ------------- Path parameter "login_id" -------------
	var loginID string

	if err := runtime.BindStyledParameter("simple", false, "login_id", chi.URLParam(r, "login_id"), &loginID); err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{err, "login_id"})
		return
	}

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.Get2faEnabled(w, r, loginID)
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
		r.Post("/2fa", wrapper.Post2faValidate)
		r.Post("/2fa/send", wrapper.Post2faSend)
		r.Get("/{login_id}/2fa/enabled", wrapper.Get2faEnabled)
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

	"H4sIAAAAAAAC/9SUzW7bOhCFX0WYe5dK7Lo77lKgDbwoEDRAN0EQTMSRzYB/JUduDUPvXgwtV5ErtDDa",
	"TXfU4Ax5eL4RD9AEF4MnzxnUAXKzJYdled81DeX8iXIMPpOUYgqREhsqgkS5sywr3kcCBZmT8Rvo+/pU",
	"Cc8v1DDU8O1qE65CZBM82qsd2o5AceqoF7XxbSj7GLbStnaRUg4emaqP6HFDjjxXN3drqGFHKZvgQcGb",
	"6+X1EvoaQiSP0YCCt6VUQ0TeFpOLVYvFesjFqlwAxcZag4K7kHnV4me0RiMT1JDoS0eZ3wW9F3kTPJMv",
	"nRijNU3pXbxkMXCK6+dobNgY/2S0rNuQHDIo6DqjoT4PS7zm3ARNM0nWwF9Di0/H8lzQ4tck0qAexo3q",
	"0cBkh8dzMP10iwJECkfk5Sqr5fKiIP5P1IKC/xbjYC2GqVqcj1Q5XlNukimjAQpWLVa7AYeuhoa2s+Wy",
	"uXMO0x4U3HS8Jc9igyrp+XF30Qn0RSavf0v+XkR/izo5NHaW4kXzcAny45GTnlen/SO8jTdsfs17PUgq",
	"oWr8pjAfeR9OV+4LevL4bKmkvaEZ+Lck7N8PKvkDEzpiShnUwwGMGJMXBGrw6CS/V//TNL76VRTnqB7/",
	"MNrpdK1afHLE26DLp2Fyef7JOBYwJdzPPMYzEMbY7b5KxMnQjnQ1xFitPtxUp5OnWG6JK7R2VLYokr7/",
	"HgAA//8OR4vmWAYAAA==",
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
