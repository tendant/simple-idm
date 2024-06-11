package demoService

import (
	"github.com/go-chi/chi/v5"
)

func Routes(r *chi.Mux, handle Handle) {

	r.Group(func(r chi.Router) {
		// add auth middleware
		r.Mount("/api", Handler(&handle))
	})
}
