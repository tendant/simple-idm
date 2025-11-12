package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucket_Allow(t *testing.T) {
	// Create a bucket with capacity 5, refill rate 1 token/second
	tb := NewTokenBucket(5, 1.0)

	// Should allow 5 requests immediately (burst capacity)
	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied (bucket empty)
	if tb.Allow() {
		t.Error("6th request should be denied")
	}

	// Wait 2 seconds for 2 tokens to refill
	time.Sleep(2 * time.Second)

	// Should allow 2 more requests
	if !tb.Allow() {
		t.Error("Request after 2s should be allowed")
	}
	if !tb.Allow() {
		t.Error("2nd request after 2s should be allowed")
	}

	// Next request should be denied again
	if tb.Allow() {
		t.Error("3rd request after 2s should be denied")
	}
}

func TestTokenBucket_Reset(t *testing.T) {
	tb := NewTokenBucket(3, 1.0)

	// Drain the bucket
	for i := 0; i < 3; i++ {
		tb.Allow()
	}

	// Should be empty
	if tb.Allow() {
		t.Error("Bucket should be empty")
	}

	// Reset
	tb.Reset()

	// Should be full again
	for i := 0; i < 3; i++ {
		if !tb.Allow() {
			t.Errorf("Request %d should be allowed after reset", i+1)
		}
	}
}

func TestTokenBucket_Tokens(t *testing.T) {
	tb := NewTokenBucket(10, 1.0)

	tokens := tb.Tokens()
	if tokens != 10.0 {
		t.Errorf("Expected 10 tokens, got %f", tokens)
	}

	// Use one token
	tb.Allow()

	tokens = tb.Tokens()
	if tokens != 9.0 {
		t.Errorf("Expected 9 tokens after one request, got %f", tokens)
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	// Create limiter: 2 requests burst, 1 per second
	rl := NewRateLimiter(2, 1.0, 0)

	// First two requests for key1 should succeed
	if !rl.Allow("key1") {
		t.Error("First request for key1 should be allowed")
	}
	if !rl.Allow("key1") {
		t.Error("Second request for key1 should be allowed")
	}

	// Third request should fail (bucket empty)
	if rl.Allow("key1") {
		t.Error("Third request for key1 should be denied")
	}

	// Requests for key2 should succeed (separate bucket)
	if !rl.Allow("key2") {
		t.Error("First request for key2 should be allowed")
	}
	if !rl.Allow("key2") {
		t.Error("Second request for key2 should be allowed")
	}

	// Wait for refill
	time.Sleep(1100 * time.Millisecond)

	// Should allow one more request for key1
	if !rl.Allow("key1") {
		t.Error("Request after 1s should be allowed")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(1, 1.0, 0)

	// Drain the bucket for key1
	rl.Allow("key1")

	// Should be denied
	if rl.Allow("key1") {
		t.Error("Second request should be denied")
	}

	// Reset key1
	rl.Reset("key1")

	// Should be allowed again
	if !rl.Allow("key1") {
		t.Error("Request after reset should be allowed")
	}
}

func TestRateLimiter_Remove(t *testing.T) {
	rl := NewRateLimiter(5, 1.0, 0)

	// Make a request to create a bucket
	rl.Allow("key1")

	stats := rl.GetStats()
	if stats.ActiveBuckets != 1 {
		t.Errorf("Expected 1 active bucket, got %d", stats.ActiveBuckets)
	}

	// Remove the bucket
	rl.Remove("key1")

	stats = rl.GetStats()
	if stats.ActiveBuckets != 0 {
		t.Errorf("Expected 0 active buckets after removal, got %d", stats.ActiveBuckets)
	}
}

func TestRateLimiter_Stats(t *testing.T) {
	rl := NewRateLimiter(10, 5.0, 0)

	// Create buckets for multiple keys
	rl.Allow("key1")
	rl.Allow("key2")
	rl.Allow("key3")

	stats := rl.GetStats()

	if stats.ActiveBuckets != 3 {
		t.Errorf("Expected 3 active buckets, got %d", stats.ActiveBuckets)
	}

	if stats.TotalCapacity != 10 {
		t.Errorf("Expected capacity 10, got %d", stats.TotalCapacity)
	}

	if stats.RefillRate != 5.0 {
		t.Errorf("Expected refill rate 5.0, got %f", stats.RefillRate)
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	// Create limiter with 100ms TTL
	rl := NewRateLimiter(5, 1.0, 200*time.Millisecond)

	// Create a bucket
	rl.Allow("key1")

	stats := rl.GetStats()
	if stats.ActiveBuckets != 1 {
		t.Errorf("Expected 1 active bucket, got %d", stats.ActiveBuckets)
	}

	// Wait for cleanup (TTL + some margin)
	time.Sleep(400 * time.Millisecond)

	stats = rl.GetStats()
	if stats.ActiveBuckets != 0 {
		t.Errorf("Expected 0 active buckets after cleanup, got %d", stats.ActiveBuckets)
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(100, 100.0, 0)

	// Simulate concurrent requests
	done := make(chan bool)
	numGoroutines := 10
	requestsPerGoroutine := 20

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < requestsPerGoroutine; j++ {
				rl.Allow("concurrent-test")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Should not panic and stats should be consistent
	stats := rl.GetStats()
	if stats.ActiveBuckets != 1 {
		t.Errorf("Expected 1 active bucket, got %d", stats.ActiveBuckets)
	}
}

func BenchmarkTokenBucket_Allow(b *testing.B) {
	tb := NewTokenBucket(1000000, 1000000.0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.Allow()
	}
}

func BenchmarkRateLimiter_Allow(b *testing.B) {
	rl := NewRateLimiter(1000000, 1000000.0, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("benchmark-key")
	}
}

func BenchmarkRateLimiter_AllowConcurrent(b *testing.B) {
	rl := NewRateLimiter(1000000, 1000000.0, 0)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow("benchmark-key")
		}
	})
}
