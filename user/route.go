package user

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Handle struct {
	userService *UserService
}

func NewHandle(userService *UserService) Handle {
	return Handle{
		userService: userService,
	}
}

// Get a list of users
// (GET /user)
func (h Handle) GetUser(w http.ResponseWriter, r *http.Request) *Response {
	return nil
}

// Create a new user
// (POST /user)
func (h Handle) PostUser(w http.ResponseWriter, r *http.Request) *Response {
	return nil
}

// Delete user by UUID
// (DELETE /user/{uuid})
func (h Handle) DeleteUserUUID(w http.ResponseWriter, r *http.Request, uuid string) *Response {
	return nil
}

// Get user details by UUID
// (GET /user/{uuid})
func (h Handle) GetUserUUID(w http.ResponseWriter, r *http.Request, uuid string) *Response {
	return nil
}

// Update user details by UUID
// (PUT /user/{uuid})
func (h Handle) PutUserUUID(w http.ResponseWriter, r *http.Request, uuid string) *Response {
	return nil
}

func Routes(r *chi.Mux, handle Handle) {

	r.Group(func(r chi.Router) {
		// add auth middleware
		r.Mount("/api/v4", Handler(&handle))
	})
}
