package ratelimit

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/jwtauth/v5"
)

// Config holds rate limiting configuration
type Config struct {
	// Global rate limiting
	GlobalEnabled    bool
	GlobalCapacity   int     // Max burst
	GlobalRefillRate float64 // Requests per second

	// Per-IP rate limiting
	PerIPEnabled    bool
	PerIPCapacity   int
	PerIPRefillRate float64

	// Per-User rate limiting (for authenticated requests)
	PerUserEnabled    bool
	PerUserCapacity   int
	PerUserRefillRate float64

	// Endpoint-specific rate limiting
	EndpointLimits map[string]EndpointLimit

	// Bucket TTL (how long to keep inactive buckets in memory)
	BucketTTL time.Duration

	// Headers to include in response
	IncludeHeaders bool
}

// EndpointLimit defines rate limits for a specific endpoint
type EndpointLimit struct {
	Capacity   int
	RefillRate float64
}

// DefaultConfig returns a sensible default configuration
// Note: EndpointLimits should be configured by the caller based on their
// specific route configuration and prefix settings. No default endpoint
// limits are provided to avoid hardcoded URIs.
func DefaultConfig() *Config {
	return &Config{
		// Global: 1000 requests per minute
		GlobalEnabled:    true,
		GlobalCapacity:   1000,
		GlobalRefillRate: 1000.0 / 60.0, // ~16.67 req/s

		// Per-IP: 100 requests per minute
		PerIPEnabled:    true,
		PerIPCapacity:   100,
		PerIPRefillRate: 100.0 / 60.0, // ~1.67 req/s

		// Per-User: 200 requests per minute (higher than IP for authenticated users)
		PerUserEnabled:    true,
		PerUserCapacity:   200,
		PerUserRefillRate: 200.0 / 60.0, // ~3.33 req/s

		// Keep buckets for 1 hour after last use
		BucketTTL: 1 * time.Hour,

		// Include rate limit headers in response
		IncludeHeaders: true,

		// Endpoint-specific limits should be configured by the caller
		// Example:
		//   EndpointLimits: map[string]EndpointLimit{
		//     "POST /api/v1/idm/auth/login": {
		//       Capacity:   10,
		//       RefillRate: 10.0 / 60.0, // 10 per minute
		//     },
		//   }
		EndpointLimits: make(map[string]EndpointLimit),
	}
}

// Middleware holds the rate limiting middleware state
type Middleware struct {
	config           *Config
	globalLimiter    *RateLimiter
	ipLimiter        *RateLimiter
	userLimiter      *RateLimiter
	endpointLimiters map[string]*RateLimiter
}

// NewMiddleware creates a new rate limiting middleware
func NewMiddleware(config *Config) *Middleware {
	if config == nil {
		config = DefaultConfig()
	}

	m := &Middleware{
		config:           config,
		endpointLimiters: make(map[string]*RateLimiter),
	}

	// Initialize global limiter
	if config.GlobalEnabled {
		m.globalLimiter = NewRateLimiter(
			config.GlobalCapacity,
			config.GlobalRefillRate,
			config.BucketTTL,
		)
	}

	// Initialize per-IP limiter
	if config.PerIPEnabled {
		m.ipLimiter = NewRateLimiter(
			config.PerIPCapacity,
			config.PerIPRefillRate,
			config.BucketTTL,
		)
	}

	// Initialize per-user limiter
	if config.PerUserEnabled {
		m.userLimiter = NewRateLimiter(
			config.PerUserCapacity,
			config.PerUserRefillRate,
			config.BucketTTL,
		)
	}

	// Initialize endpoint-specific limiters
	for endpoint, limit := range config.EndpointLimits {
		m.endpointLimiters[endpoint] = NewRateLimiter(
			limit.Capacity,
			limit.RefillRate,
			config.BucketTTL,
		)
	}

	return m
}

// Handler returns the rate limiting middleware handler
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check global limit
		if m.config.GlobalEnabled && !m.globalLimiter.Allow("global") {
			m.rateLimitExceeded(w, r, "global")
			return
		}

		// Check per-IP limit
		ip := getClientIP(r)
		if m.config.PerIPEnabled && ip != "" && !m.ipLimiter.Allow(ip) {
			m.rateLimitExceeded(w, r, "ip")
			return
		}

		// Check per-user limit (if authenticated)
		userID := getUserID(r)
		if m.config.PerUserEnabled && userID != "" && !m.userLimiter.Allow(userID) {
			m.rateLimitExceeded(w, r, "user")
			return
		}

		// Check endpoint-specific limits
		endpointKey := r.Method + " " + r.URL.Path
		if limiter, exists := m.endpointLimiters[endpointKey]; exists {
			if !limiter.Allow(ip + ":" + endpointKey) {
				m.rateLimitExceeded(w, r, "endpoint")
				return
			}
		}

		// Add rate limit headers if enabled
		if m.config.IncludeHeaders {
			m.addRateLimitHeaders(w, ip, userID)
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitExceeded handles rate limit exceeded responses
func (m *Middleware) rateLimitExceeded(w http.ResponseWriter, r *http.Request, limitType string) {
	slog.Warn("Rate limit exceeded",
		"type", limitType,
		"ip", getClientIP(r),
		"user", getUserID(r),
		"path", r.URL.Path,
		"method", r.Method,
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "60") // Suggest retry after 60 seconds
	w.WriteHeader(http.StatusTooManyRequests)

	w.Write([]byte(fmt.Sprintf(`{
		"error": "rate_limit_exceeded",
		"message": "Too many requests. Please try again later.",
		"type": "%s"
	}`, limitType)))
}

// addRateLimitHeaders adds rate limit information headers
func (m *Middleware) addRateLimitHeaders(w http.ResponseWriter, ip, userID string) {
	// Add standard rate limit headers
	// These headers help clients understand their rate limit status

	if m.config.PerIPEnabled && ip != "" {
		w.Header().Set("X-RateLimit-Limit-IP", fmt.Sprintf("%d", m.config.PerIPCapacity))
	}

	if m.config.PerUserEnabled && userID != "" {
		w.Header().Set("X-RateLimit-Limit-User", fmt.Sprintf("%d", m.config.PerUserCapacity))
	}
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (set by proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (set by some proxies/load balancers)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	// RemoteAddr is in format "IP:port", we only want the IP
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}

	return addr
}

// getUserID extracts the user ID from JWT token in the request context
func getUserID(r *http.Request) string {
	// Try to get user ID from JWT claims
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		return ""
	}

	if claims == nil {
		return ""
	}

	// Try standard JWT claim "sub" (subject)
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}

	// Try "user_id" claim
	if userID, ok := claims["user_id"].(string); ok && userID != "" {
		return userID
	}

	// Try "id" claim
	if id, ok := claims["id"].(string); ok && id != "" {
		return id
	}

	return ""
}

// GetStats returns statistics about all rate limiters
func (m *Middleware) GetStats() map[string]Stats {
	stats := make(map[string]Stats)

	if m.globalLimiter != nil {
		stats["global"] = m.globalLimiter.GetStats()
	}

	if m.ipLimiter != nil {
		stats["ip"] = m.ipLimiter.GetStats()
	}

	if m.userLimiter != nil {
		stats["user"] = m.userLimiter.GetStats()
	}

	for endpoint, limiter := range m.endpointLimiters {
		stats["endpoint:"+endpoint] = limiter.GetStats()
	}

	return stats
}

// Reset resets rate limits for a specific IP or user
func (m *Middleware) Reset(key string) {
	if m.ipLimiter != nil {
		m.ipLimiter.Reset(key)
	}
	if m.userLimiter != nil {
		m.userLimiter.Reset(key)
	}
}
