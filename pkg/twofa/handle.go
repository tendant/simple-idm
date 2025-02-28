package twofa

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/google/uuid"
)

type Handle struct {
	twoFaService *TwoFaService
}

func NewHandle(twoFaService *TwoFaService) Handle {
	return Handle{
		twoFaService: twoFaService,
	}
}

// Initiate sending 2fa code
// (POST /2fa:init)
func (h Handle) Post2faInit(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

	data := &Post2faInitJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	// FIXME: read the login id from session cookies
	loginId, err := uuid.Parse(data.LoginID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid login id",
		}
	}

	err = h.twoFaService.InitTwoFa(r.Context(), loginId, data.TwofaType, data.Email)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to init 2fa: " + err.Error(),
		}
	}

	return Post2faInitJSON200Response(resp)
}

// Authenticate 2fa passcode
// (POST /2fa)
func (h Handle) Post2faValidate(w http.ResponseWriter, r *http.Request) *Response {
	var resp SuccessResponse

	data := &Post2faValidateJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	loginId, err := uuid.Parse(data.LoginID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid login id",
		}
	}

	valid, err := h.twoFaService.Validate2faPasscode(r.Context(), loginId, data.TwofaType, data.Passcode)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to validate 2fa: " + err.Error(),
		}
	}

	if !valid {
		return &Response{
			Code: http.StatusBadRequest,
			body: "2fa validation failed",
		}
	}

	return Post2faValidateJSON200Response(resp)
}

// Get all enabled 2fas
// (GET /2fa/enabled)
func (h Handle) Get2faEnabled(w http.ResponseWriter, r *http.Request, loginID string) *Response {
	// Get login ID from path parameter
	loginId, err := uuid.Parse(loginID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid login id",
		}
	}

	// Find enabled 2FA methods
	twoFAs, err := h.twoFaService.FindEnabledTwoFAs(r.Context(), loginId)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: "failed to validate 2fa: " + err.Error(),
		}
	}

	return Get2faEnabledJSON200Response(struct {
		N2faMethods []string `json:"2fa_methods,omitempty"`
	}{
		N2faMethods: twoFAs,
	})
}
