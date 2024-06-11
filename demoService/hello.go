package demoService

import (
	"net/http"

	"github.com/go-chi/render"
)

func (h *Handle) GetHello(w http.ResponseWriter, r *http.Request, param GetHelloParams) *Response {

	if param.Name == "" {
		errorRsp := Response{
			body: "invalid name",
			Code: http.StatusBadRequest,
		}
		return &errorRsp
	}

	greeting := Greeting{
		ID:   1,
		Name: param.Name,
	}

	return GetHelloJSON200Response(greeting)
}

func (h *Handle) GetHelloID(w http.ResponseWriter, r *http.Request, id int, param GetHelloIDParams) *Response {
	if param.Name == "" {
		errorRsp := Response{
			body: "invalid name",
			Code: http.StatusBadRequest,
		}
		return &errorRsp
	}

	greeting := Greeting{
		ID:   id,
		Name: param.Name,
	}

	return GetHelloIDJSON200Response(greeting)
}

func (h *Handle) PostHello(w http.ResponseWriter, r *http.Request) *Response {

	data := PostHelloJSONRequestBody{}
	err := render.DecodeJSON(r.Body, &data)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: "unable to parse body",
		}
	}

	greeting := Greeting{
		ID:   3,
		Name: *data.Name,
	}

	return PostHelloJSON200Response(greeting)
}
