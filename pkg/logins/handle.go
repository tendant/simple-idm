package logins

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/logins/loginsdb"
)

// LoginsHandle handles HTTP requests for login management
type LoginsHandle struct {
	loginService *LoginsService
}

// Ensure LoginsHandle implements ServerInterface
var _ ServerInterface = (*LoginsHandle)(nil)

// NewHandle creates a new login handler
func NewHandle(loginService *LoginsService) *LoginsHandle {
	return &LoginsHandle{
		loginService: loginService,
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
		r.Put("/{id}/password", h.UpdatePassword)
		r.Post("/{id}/2fa/enable", h.EnableTwoFactor)
		r.Post("/{id}/2fa/disable", h.DisableTwoFactor)
		r.Post("/{id}/backup-codes", h.GenerateBackupCodes)
	})
}

// ListLogins handles the request to list logins
func (h *LoginsHandle) ListLogins(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	search := r.URL.Query().Get("search")

	limit := int32(20)
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

	var logins []loginsdb.Login
	var total int64
	var err error

	if search != "" {
		logins, err = h.loginService.SearchLogins(r.Context(), search, limit, offset)
		if err != nil {
			http.Error(w, "Failed to search logins: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// For simplicity, we're not getting the total count for search results
		total = int64(len(logins))
	} else {
		logins, total, err = h.loginService.ListLogins(r.Context(), limit, offset)
		if err != nil {
			http.Error(w, "Failed to list logins: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Prepare response
	response := struct {
		Logins []loginsdb.Login `json:"logins"`
		Total  int64            `json:"total"`
	}{
		Logins: logins,
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
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
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
	login, err := h.loginService.CreateLogin(r.Context(), request.Username, request.Password, "admin")
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
	var request struct {
		Username string `json:"username"`
	}
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
	login, err := h.loginService.UpdateLogin(r.Context(), id, request.Username)
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

// UpdatePassword handles the request to update a login's password
func (h *LoginsHandle) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	// Parse login ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Parse request body
	var request struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	// Update password
	login, err := h.loginService.UpdatePassword(r.Context(), id, request.Password)
	if err != nil {
		http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(login)
}

// EnableTwoFactor handles the request to enable two-factor authentication
func (h *LoginsHandle) EnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	// Parse login ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Parse request body
	var request struct {
		Secret           string `json:"secret"`
		VerificationCode string `json:"verification_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Secret == "" || request.VerificationCode == "" {
		http.Error(w, "Secret and verification code are required", http.StatusBadRequest)
		return
	}

	// TODO: Verify the verification code against the secret
	// For now, we'll just enable 2FA without verification

	// Enable 2FA
	login, err := h.loginService.EnableTwoFactor(r.Context(), id, request.Secret)
	if err != nil {
		http.Error(w, "Failed to enable two-factor authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(login)
}

// DisableTwoFactor handles the request to disable two-factor authentication
func (h *LoginsHandle) DisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	// Parse login ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Disable 2FA
	login, err := h.loginService.DisableTwoFactor(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to disable two-factor authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(login)
}

// GenerateBackupCodes handles the request to generate new backup codes
func (h *LoginsHandle) GenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	// Parse login ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Generate backup codes
	backupCodes, err := h.loginService.GenerateBackupCodes(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to generate backup codes: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		BackupCodes []string `json:"backup_codes"`
	}{
		BackupCodes: backupCodes,
	})
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

	// Call the handler method
	h.ListLogins(w, r)
	return nil
}

// Post implements ServerInterface.Post
func (h *LoginsHandle) Post(w http.ResponseWriter, r *http.Request) *Response {
	h.CreateLogin(w, r)
	return nil
}

// PostLoginsId2faEnable implements ServerInterface.PostLoginsId2faEnable
func (h *LoginsHandle) PostLoginsId2faEnable(w http.ResponseWriter, r *http.Request, id string) *Response {
	// Set the ID in the URL context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	h.EnableTwoFactor(w, r)
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

// PostId2faEnable implements ServerInterface.PostId2faEnable
func (h *LoginsHandle) PostId2faEnable(w http.ResponseWriter, r *http.Request, id string) *Response {
	// Set the ID in the URL context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	h.EnableTwoFactor(w, r)
	return nil
}

// PostIDBackupCodes implements ServerInterface.PostIDBackupCodes
func (h *LoginsHandle) PostIDBackupCodes(w http.ResponseWriter, r *http.Request, id string) *Response {
	// Set the ID in the URL context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	h.GenerateBackupCodes(w, r)
	return nil
}

// PutIDPassword implements ServerInterface.PutIDPassword
func (h *LoginsHandle) PutIDPassword(w http.ResponseWriter, r *http.Request, id string) *Response {
	// Set the ID in the URL context
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	h.UpdatePassword(w, r)
	return nil
}
