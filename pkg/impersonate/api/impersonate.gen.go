// Package impersonate provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/discord-gophers/goapi-gen version v0.3.0 DO NOT EDIT.
package impersonate

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

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// ErrorResponse defines model for ErrorResponse.
type ErrorResponse struct {
	// Error code
	Code *string `json:"code,omitempty"`

	// Error message
	Error string `json:"error"`
}

// Empty response for successful operation
type SuccessResponse map[string]interface{}

// CreateImpersonateJSONBody defines parameters for CreateImpersonate.
type CreateImpersonateJSONBody struct {
	// UUID of the delegator user
	DelegatorUserUUID string `json:"delegator_user_uuid"`
}

// CreateImpersonateJSONRequestBody defines body for CreateImpersonate for application/json ContentType.
type CreateImpersonateJSONRequestBody CreateImpersonateJSONBody

// Bind implements render.Binder.
func (CreateImpersonateJSONRequestBody) Bind(*http.Request) error {
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

// CreateImpersonateJSON200Response is a constructor method for a CreateImpersonate response.
// A *Response is returned with the configured status code and content type from the spec.
func CreateImpersonateJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// CreateImpersonateJSON400Response is a constructor method for a CreateImpersonate response.
// A *Response is returned with the configured status code and content type from the spec.
func CreateImpersonateJSON400Response(body ErrorResponse) *Response {
	return &Response{
		body:        body,
		Code:        400,
		contentType: "application/json",
	}
}

// CreateImpersonateJSON401Response is a constructor method for a CreateImpersonate response.
// A *Response is returned with the configured status code and content type from the spec.
func CreateImpersonateJSON401Response(body ErrorResponse) *Response {
	return &Response{
		body:        body,
		Code:        401,
		contentType: "application/json",
	}
}

// CreateImpersonateJSON403Response is a constructor method for a CreateImpersonate response.
// A *Response is returned with the configured status code and content type from the spec.
func CreateImpersonateJSON403Response(body ErrorResponse) *Response {
	return &Response{
		body:        body,
		Code:        403,
		contentType: "application/json",
	}
}

// CreateImpersonateBackJSON200Response is a constructor method for a CreateImpersonateBack response.
// A *Response is returned with the configured status code and content type from the spec.
func CreateImpersonateBackJSON200Response(body SuccessResponse) *Response {
	return &Response{
		body:        body,
		Code:        200,
		contentType: "application/json",
	}
}

// CreateImpersonateBackJSON400Response is a constructor method for a CreateImpersonateBack response.
// A *Response is returned with the configured status code and content type from the spec.
func CreateImpersonateBackJSON400Response(body ErrorResponse) *Response {
	return &Response{
		body:        body,
		Code:        400,
		contentType: "application/json",
	}
}

// CreateImpersonateBackJSON401Response is a constructor method for a CreateImpersonateBack response.
// A *Response is returned with the configured status code and content type from the spec.
func CreateImpersonateBackJSON401Response(body ErrorResponse) *Response {
	return &Response{
		body:        body,
		Code:        401,
		contentType: "application/json",
	}
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Create impersonation session
	// (POST /)
	CreateImpersonate(w http.ResponseWriter, r *http.Request) *Response
	// End impersonation session
	// (POST /back)
	CreateImpersonateBack(w http.ResponseWriter, r *http.Request) *Response
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler          ServerInterface
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// CreateImpersonate operation middleware
func (siw *ServerInterfaceWrapper) CreateImpersonate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.CreateImpersonate(w, r)
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

// CreateImpersonateBack operation middleware
func (siw *ServerInterfaceWrapper) CreateImpersonateBack(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := siw.Handler.CreateImpersonateBack(w, r)
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
		r.Post("/", wrapper.CreateImpersonate)
		r.Post("/back", wrapper.CreateImpersonateBack)
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

	"H4sIAAAAAAAC/+RVTW8bNxD9KwRboJe1Vkl82lPj1gUM9JDW8SkwgjE5kpjscujhrFQ10H8vhivL+ljD",
	"LlAYBXJbzHLee/PxyG/WUZcoYpRsm282uwV2UD4vmYn/xJwoZtRAYkrIErD8duRL1GN2HJIEirYZkkz5",
	"V1lZJ7SNzcIhzu2msqh/n0rqMGeYj+RtKst43wdGb5tPW5Db3TG6+4JOFP66dw5z3td8RNQlWRve/jcz",
	"YpOHnFnfGq0OyskTbNUQ4oyGwqOAE/3EDkJrGxuWEH8W4gRzmjjqbGUjdArwcQiajwga7VmPL0RSbup6",
	"tVpN9rM21ZHeqy4hZ4ogaN5/uCqCPbY4B0Fv+oxsoMhXxUFaPM2xlV0i5wHvzWQ6mSoNJYyQgm3suxKq",
	"bAJZlLnWZdSU5bR9vzCCYDYQTdixBIomY1YGA21LqxDnBnYy0QhtRT5GiX/KGqQ+ii1qhsZf+R3LXhl2",
	"mD9muSC/fhgBxqIQUmqDK9n1l6wyH5b4dGV37J+1dZ/7PvjTIm9urn41NDOywEe5pde2sjPiDsQ2tuQ+",
	"t6ljfLeju/WYJdxjCQw7WnS/nU7/VdU/Ms5sY3+oH71db41dH3uk0B924HpniXZt5hh1OOj3Rq4z/Yox",
	"6yad/4faDm+cEWUX4M12FQbuN6/HfROhlwVx+Bv9QP7u9ch/I74L3mM0Z+ZGbe8Js4kkZgFLNAm5C4MF",
	"hfYHVVYy910HvN5Za9y85Wh9B+7r0xfAZfS5GMP1zBjlqWsg6pik55hVjyYQh3mI0A6XVmnaXy+w/oXK",
	"+V+6YXCAljdUql8HRX7H5jjYucvon1w4PYis75NtPh0v2wcm37vte3z4cEIKb/dfTg3U4LsQ6+W53VTH",
	"UH+8H4FIZwP35B52WBHlOazfyUF7ANfUdavBBWVpzqfT6XMQ131cYZazexiTpXqWQTsEvHbEiXTjHLB/",
	"SakP2InJj6K/GPp2808AAAD//6ekwf8dCgAA",
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
