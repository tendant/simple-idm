// Package audit provides middleware for auditing HTTP requests
package audit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/ce-client/ce"
	"github.com/tendant/simple-idm/pkg/login"
)

// Config holds the configuration for the audit middleware
type Config struct {
	// NoticeVersion specifies the version for audit notices
	NoticeVersion string
	// Source specifies the source of the audit events
	Source string
	// EventType specifies the type of audit events
	EventType string
	// EventClient is the client used to send audit events
	EventClient *ce.EventClient
}

// Middleware handles HTTP request auditing
type Middleware struct {
	config Config
}

// NewMiddleware creates a new audit middleware instance
func NewMiddleware(config Config) (*Middleware, error) {
	if config.EventClient == nil {
		return nil, fmt.Errorf("event client is required")
	}
	
	if config.Source == "" {
		config.Source = "app-server"
	}
	
	if config.EventType == "" {
		config.EventType = "audit.internal.app-server"
	}

	return &Middleware{
		config: config,
	}, nil
}

// AuditEvent represents an audit event
type AuditEvent struct {
	UserID    uuid.UUID
	URI       string
	Method    string
	Message   string
	Timestamp time.Time
	Metadata  map[string]interface{}
}

// AuditAuthMiddleware is an HTTP middleware that audits authenticated requests
func (m *Middleware) AuditAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var event AuditEvent
		event.URI = r.RequestURI
		event.Method = r.Method
		event.Timestamp = time.Now()

		// Extract user information from context
		if idmUser, ok := ctx.Value(login.AuthUserKey).(*login.AuthUser); ok {
			event.UserID = idmUser.UserUUID
		} else {
			event.Message = "No jwt token"
		}

		// Audit the request asynchronously
		go m.auditRequest(ctx, event)

		// Continue with the request
		next.ServeHTTP(w, r)
	})
}

// auditRequest sends an audit event asynchronously
func (m *Middleware) auditRequest(ctx context.Context, event AuditEvent) {
	userID := ""
	if event.UserID != uuid.Nil {
		userID = event.UserID.String()
	}

	m.config.EventClient.SendEventAsync(ce.EventGeneric{
		Subject: m.config.NoticeVersion,
		Source:  m.config.Source,
		Type:    m.config.EventType,
		Data: map[string]interface{}{
			"user":      userID,
			"uri":       event.URI,
			"method":    event.Method,
			"message":   event.Message,
			"timestamp": event.Timestamp.Format(time.RFC3339),
			"metadata":  event.Metadata,
		},
	})
}

// WithMetadata adds metadata to the audit event
func (e AuditEvent) WithMetadata(key string, value interface{}) AuditEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}
