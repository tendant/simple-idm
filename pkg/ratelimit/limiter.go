package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket implements the token bucket algorithm for rate limiting
type TokenBucket struct {
	capacity   int           // Maximum number of tokens
	tokens     float64       // Current number of tokens
	refillRate float64       // Tokens added per second
	lastRefill time.Time     // Last time tokens were refilled
	mu         sync.Mutex    // Mutex for thread safety
}

// NewTokenBucket creates a new token bucket rate limiter
// capacity: Maximum number of requests allowed in a burst
// refillRate: Number of requests allowed per second
func NewTokenBucket(capacity int, refillRate float64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     float64(capacity),
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request should be allowed
// Returns true if the request is allowed, false if rate limited
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tokensToAdd := elapsed * tb.refillRate

	tb.tokens = min(float64(tb.capacity), tb.tokens+tokensToAdd)
	tb.lastRefill = now

	// Check if we have at least one token
	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}

	return false
}

// Tokens returns the current number of available tokens
func (tb *TokenBucket) Tokens() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens
}

// Reset resets the token bucket to full capacity
func (tb *TokenBucket) Reset() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.tokens = float64(tb.capacity)
	tb.lastRefill = time.Now()
}

// RateLimiter manages multiple token buckets
type RateLimiter struct {
	buckets    map[string]*TokenBucket
	capacity   int
	refillRate float64
	mu         sync.RWMutex
	ttl        time.Duration // Time to live for inactive buckets
}

// NewRateLimiter creates a new rate limiter
// capacity: Maximum number of requests allowed in a burst per key
// refillRate: Number of requests allowed per second per key
// ttl: Time to keep inactive buckets in memory (0 = forever)
func NewRateLimiter(capacity int, refillRate float64, ttl time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets:    make(map[string]*TokenBucket),
		capacity:   capacity,
		refillRate: refillRate,
		ttl:        ttl,
	}

	// Start cleanup goroutine if TTL is set
	if ttl > 0 {
		go rl.cleanup()
	}

	return rl
}

// Allow checks if a request for the given key should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = NewTokenBucket(rl.capacity, rl.refillRate)
		rl.buckets[key] = bucket
	}
	rl.mu.Unlock()

	return bucket.Allow()
}

// Reset resets the rate limiter for a specific key
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if bucket, exists := rl.buckets[key]; exists {
		bucket.Reset()
	}
}

// Remove removes a specific key from the rate limiter
func (rl *RateLimiter) Remove(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
}

// cleanup periodically removes inactive buckets
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.ttl)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.buckets {
			// Remove bucket if it hasn't been used recently
			if now.Sub(bucket.lastRefill) > rl.ttl {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// Stats returns statistics about the rate limiter
type Stats struct {
	ActiveBuckets int
	TotalCapacity int
	RefillRate    float64
}

// GetStats returns current statistics
func (rl *RateLimiter) GetStats() Stats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return Stats{
		ActiveBuckets: len(rl.buckets),
		TotalCapacity: rl.capacity,
		RefillRate:    rl.refillRate,
	}
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
