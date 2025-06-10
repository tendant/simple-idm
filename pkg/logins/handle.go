package logins

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam"
	"github.com/tendant/simple-idm/pkg/role"
	"github.com/tendant/simple-idm/pkg/twofa"
)

// LoginsHandle handles HTTP requests for login management
type LoginsHandle struct {
	loginService     *LoginsService
	twoFactorService twofa.TwoFactorService
	iamService       *iam.IamService
	roleService      *role.RoleService
}

// Ensure LoginsHandle implements ServerInterface
var _ ServerInterface = (*LoginsHandle)(nil)

// NewHandle creates a new login handler
func NewHandle(loginService *LoginsService, twoFactorService twofa.TwoFactorService) *LoginsHandle {
	return &LoginsHandle{
		loginService:     loginService,
		twoFactorService: twoFactorService,
	}
}

// RegisterRoutes registers the login routes
func (h *LoginsHandle) RegisterRoutes(r chi.Router) {
	r.Route("/logins", func(r chi.Router) {
		r.Get("/", h.ListLogins)
		r.Post("/", h.CreateLogin)
		r.Get("/{id}", h.GetLogin)
		r.Put("/{id}", h.UpdateLogin)
		r.Delete("/{id}", h.DeleteLogin)
		r.Post("/register", h.RegisterUser)
	})
}

// ListLogins handles the request to list logins
func (h *LoginsHandle) ListLogins(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	search := r.URL.Query().Get("search")

	limit := int32(50)
	if limitStr != "" {
		limitInt, err := strconv.Atoi(limitStr)
		if err == nil {
			limit = int32(limitInt)
		}
	}

	offset := int32(0)
	if offsetStr != "" {
		offsetInt, err := strconv.Atoi(offsetStr)
		if err == nil {
			offset = int32(offsetInt)
		}
	}

	var loginModels []LoginModel
	var total int64
	var err error

	if search != "" {
		loginModels, err = h.loginService.SearchLogins(r.Context(), search, limit, offset)
		if err != nil {
			http.Error(w, "Failed to search logins: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// For simplicity, we're not getting the total count for search results
		total = int64(len(loginModels))
	} else {
		loginModels, total, err = h.loginService.ListLogins(r.Context(), limit, offset)
		if err != nil {
			http.Error(w, "Failed to list logins: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Prepare response
	response := LoginListResponse{
		Logins: loginModels,
		Total:  total,
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// GetLogin handles the request to get a login by ID
func (h *LoginsHandle) GetLogin(w http.ResponseWriter, r *http.Request) {
	// Parse login ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Get login
	login, err := h.loginService.GetLogin(r.Context(), id)
	if err != nil {
		http.Error(w, "Login not found", http.StatusNotFound)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(login)
}

// CreateLogin handles the request to create a new login
func (h *LoginsHandle) CreateLogin(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var request LoginCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Username == "" || request.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Create login
	login, err := h.loginService.CreateLogin(r.Context(), request, "admin")
	if err != nil {
		http.Error(w, "Failed to create login: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(login)
}

// UpdateLogin handles the request to update a login
func (h *LoginsHandle) UpdateLogin(w http.ResponseWriter, r *http.Request) {
	// Parse login ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Parse request body
	var request LoginUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Update login
	login, err := h.loginService.UpdateLogin(r.Context(), id, request)
	if err != nil {
		http.Error(w, "Failed to update login: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(login)
}

// DeleteLogin handles the request to delete a login
func (h *LoginsHandle) DeleteLogin(w http.ResponseWriter, r *http.Request) {
	// Parse login ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Delete login
	err = h.loginService.DeleteLogin(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to delete login: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.WriteHeader(http.StatusNoContent)
}

// ServerInterface implementation

// Get implements ServerInterface.Get
func (h *LoginsHandle) Get(w http.ResponseWriter, r *http.Request, params GetParams) *Response {
	// Set query parameters
	q := r.URL.Query()
	if params.Limit != nil {
		q.Set("limit", strconv.Itoa(*params.Limit))
	}
	if params.Offset != nil {
		q.Set("offset", strconv.Itoa(*params.Offset))
	}
	if params.Search != nil {
		q.Set("search", *params.Search)
	}
	r.URL.RawQuery = q.Encode()

	// Get the logins
	limit := int32(50)
	offset := int32(0)
	search := ""

	if params.Limit != nil {
		limit = int32(*params.Limit)
	}
	if params.Offset != nil {
		offset = int32(*params.Offset)
	}
	if params.Search != nil {
		search = *params.Search
	}

	var loginModels []LoginModel
	var err error

	if search != "" {
		loginModels, err = h.loginService.SearchLogins(r.Context(), search, limit, offset)
		if err != nil {
			http.Error(w, "Failed to search logins: "+err.Error(), http.StatusInternalServerError)
			return nil
		}
	} else {
		loginModels, _, err = h.loginService.ListLogins(r.Context(), limit, offset)
		if err != nil {
			http.Error(w, "Failed to list logins: "+err.Error(), http.StatusInternalServerError)
			return nil
		}
	}

	// Write response - just return the array directly
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginModels)
	return nil
}

// Post implements ServerInterface.Post
func (h *LoginsHandle) Post(w http.ResponseWriter, r *http.Request) *Response {
	h.CreateLogin(w, r)
	return nil
}

// DeleteID implements ServerInterface.DeleteID
func (h *LoginsHandle) DeleteID(w http.ResponseWriter, r *http.Request, id string) *Response {
	// Set the ID in the URL context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	h.DeleteLogin(w, r)
	return nil
}

// GetID implements ServerInterface.GetID
func (h *LoginsHandle) GetID(w http.ResponseWriter, r *http.Request, id string) *Response {
	// Set the ID in the URL context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	h.GetLogin(w, r)
	return nil
}

// PutID implements ServerInterface.PutID
func (h *LoginsHandle) PutID(w http.ResponseWriter, r *http.Request, id string) *Response {
	// Set the ID in the URL context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	h.UpdateLogin(w, r)
	return nil
}

func (h *LoginsHandle) RegisterUser(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var request RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if request.Username == "" || request.Password == "" || request.FullName == "" || request.Email == "" {
		http.Error(w, "Full name, username, password, and email are required", http.StatusBadRequest)
		return
	}

	// Create login request from registration request
	loginRequest := LoginCreateRequest{
		Username: request.Username,
		Password: request.Password,
	}

	// Determine role based on invitation code
	role := "demo"
	if request.InvitationCode != "" {
		// TODO: implement invitation code logic
		switch request.InvitationCode {
		default:
			role = "demo"
		}
	}

	roleID, err := h.roleService.GetRoleIdByName(r.Context(), role)
	if err != nil {
		http.Error(w, "Failed to get role ID: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create the login
	login, err := h.loginService.CreateLogin(r.Context(), loginRequest, role)
	if err != nil {
		http.Error(w, "Failed to register user: "+err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.iamService.CreateUser(r.Context(), request.Email, request.Username, request.FullName, []uuid.UUID{}, login.ID)
	if err != nil {
		http.Error(w, "Failed to register user: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Add user to role
	err = h.roleService.AddUserToRole(r.Context(), user.ID, roleID, login.Username)
	if err != nil {
		http.Error(w, "Failed to register user: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Return the created login
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(login)
}

// Get login 2FA methods
// (GET /{id}/2fa)
func (h *LoginsHandle) Get2faMethodsByLoginID(w http.ResponseWriter, r *http.Request, id string) *Response {
	loginId, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	res, err := h.twoFactorService.FindTwoFAsByLoginId(r.Context(), loginId)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": err.Error()},
		}
	}

	var (
		methods []TwoFactorMethod
		resp    TwoFactorMethods
	)

	for _, v := range res {
		methods = append(methods, TwoFactorMethod{
			TwoFactorID: v.TwoFactorId.String(),
			Type:        v.TwoFactorType,
			Enabled:     v.TwoFactorEnabled,
		})
	}

	resp.Count = len(methods)
	resp.Methods = methods

	return Get2faMethodsByLoginIDJSON200Response(resp)
}
