package twofa

import (
	"log/slog"
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

	loginId, err := uuid.Parse(data.LoginID)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "invalid login id",
		}
	}

	// get or create the 2fa secret for the login
	secret, err := h.twoFaService.GetTwoFactorSecretByLoginId(r.Context(), loginId, data.TwofaType)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "failed to get or create 2fa secret: " + err.Error(),
		}
	}

	// generate 2fa passcode
	passcode, err := Generate2faPasscode(secret)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "failed to generate 2fa passcode: " + err.Error(),
		}
	}
	slog.Info("Generated 2fa passcode", "passcode", passcode)

	// TODO: send 2fa passcode to user via email

	return Post2faInitJSON200Response(resp)
}
