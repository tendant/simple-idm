package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/sessions"
)

// Handler handles HTTP requests for session management
type Handler struct {
	service *sessions.Service
}

// NewHandler creates a new session handler
func NewHandler(service *sessions.Service) *Handler {
	return &Handler{
		service: service,
	}
}

// RegisterRoutes registers the session management routes
// These routes should be mounted under an authenticated route group
func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Get("/", h.ListSessions)
	r.Post("/revoke", h.RevokeSession)
	r.Post("/revoke-all", h.RevokeAllSessions)
}

// ListSessions handles GET /sessions - List active sessions for current user
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	loginID, err := uuid.Parse(authUser.LoginId)
	if err != nil {
		slog.Error("Invalid login ID", "login_id", authUser.LoginId, "error", err)
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Get current JTI from JWT claims
	_, claims, _ := jwtauth.FromContext(r.Context())
	currentJTI := ""
	if claims != nil {
		if jti, ok := claims["jti"].(string); ok {
			currentJTI = jti
		}
	}

	// List active sessions
	response, err := h.service.ListActiveSessionSummaries(r.Context(), loginID, currentJTI)
	if err != nil {
		slog.Error("Failed to list sessions", "login_id", loginID, "error", err)
		http.Error(w, "Failed to list sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RevokeSession handles POST /sessions/revoke - Revoke a specific session
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req sessions.RevokeSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get the session to verify ownership
	session, err := h.service.GetSession(r.Context(), req.SessionID)
	if err != nil {
		slog.Error("Session not found", "session_id", req.SessionID, "error", err)
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Verify that the session belongs to the authenticated user
	if session.LoginID.String() != authUser.LoginId {
		slog.Warn("Attempted to revoke session from different user",
			"requester_login_id", authUser.LoginId,
			"session_login_id", session.LoginID.String())
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Revoke the session
	if err := h.service.RevokeSession(r.Context(), req.SessionID); err != nil {
		slog.Error("Failed to revoke session", "session_id", req.SessionID, "error", err)
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	slog.Info("Session revoked", "session_id", req.SessionID, "login_id", authUser.LoginId)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Session revoked successfully",
	})
}

// RevokeAllSessions handles POST /sessions/revoke-all - Revoke all sessions
func (h *Handler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	loginID, err := uuid.Parse(authUser.LoginId)
	if err != nil {
		slog.Error("Invalid login ID", "login_id", authUser.LoginId, "error", err)
		http.Error(w, "Invalid login ID", http.StatusBadRequest)
		return
	}

	// Parse request body
	var req sessions.RevokeAllSessionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Default to revoking all except current if no body provided
		req.ExceptCurrentSession = true
	}

	// Get current session ID if we need to keep it active
	var currentSessionID uuid.UUID
	if req.ExceptCurrentSession {
		_, claims, _ := jwtauth.FromContext(r.Context())
		if claims != nil {
			if jti, ok := claims["jti"].(string); ok {
				session, err := h.service.GetSessionByJTI(r.Context(), jti)
				if err == nil {
					currentSessionID = session.ID
				}
			}
		}
	}

	// Revoke all sessions
	if err := h.service.RevokeAllSessions(r.Context(), loginID, req.ExceptCurrentSession, currentSessionID); err != nil {
		slog.Error("Failed to revoke all sessions", "login_id", loginID, "error", err)
		http.Error(w, "Failed to revoke all sessions", http.StatusInternalServerError)
		return
	}

	slog.Info("All sessions revoked", "login_id", loginID, "except_current", req.ExceptCurrentSession)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "All sessions revoked successfully",
	})
}
