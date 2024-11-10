// File: logwisp/src/internal/middleware/ratelimiter.go

package middleware

import (
	"context"
	"logwisp/src/pkg/logger"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiterConfig holds configuration for rate limiting
type RateLimiterConfig struct {
	// RequestsPerSecond defines the rate limit per client
	RequestsPerSecond float64
	// BurstSize defines how many requests can be made at once
	BurstSize int
	// ClientTimeout defines how long to keep client limiters
	ClientTimeout time.Duration
}

// clientInfo holds rate limiter and last access time
type clientInfo struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// rateLimiter implements a per-client rate limiting middleware
type rateLimiter struct {
	config  RateLimiterConfig
	clients sync.Map // map[string]*clientInfo
	cleanup *time.Ticker
	done    chan struct{}
}

// NewRateLimiter creates a new rate limiting middleware
func NewRateLimiter(cfg RateLimiterConfig) (Middleware, Cleanup) {
	logger.Info(context.Background(), "Creating new rate limiter",
		"requestsPerSecond", cfg.RequestsPerSecond,
		"burstSize", cfg.BurstSize,
		"clientTimeout", cfg.ClientTimeout)

	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 10
		logger.Warn(context.Background(), "Invalid requests per second, using default",
			"default", cfg.RequestsPerSecond)
	}
	if cfg.BurstSize <= 0 {
		cfg.BurstSize = 20
		logger.Warn(context.Background(), "Invalid burst size, using default",
			"default", cfg.BurstSize)
	}
	if cfg.ClientTimeout <= 0 {
		cfg.ClientTimeout = 1 * time.Hour
		logger.Warn(context.Background(), "Invalid client timeout, using default",
			"default", cfg.ClientTimeout)
	}

	rl := &rateLimiter{
		config:  cfg,
		cleanup: time.NewTicker(1 * time.Minute), // Run cleanup every minute
		done:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	logger.Info(context.Background(), "Rate limiter created")
	return rl.middleware, rl
}

// middleware implements the actual rate limiting logic
func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		logger.Debug(r.Context(), "Processing request", "clientIP", clientIP)

		// Get or create limiter for this client
		clientInfoVal, loaded := rl.clients.LoadOrStore(clientIP, &clientInfo{
			limiter: rate.NewLimiter(
				rate.Limit(rl.config.RequestsPerSecond),
				rl.config.BurstSize,
			),
			lastAccess: time.Now(),
		})
		client := clientInfoVal.(*clientInfo)

		if !loaded {
			logger.Debug(r.Context(), "Created new rate limiter for client",
				"clientIP", clientIP)
		}

		// Update last access time
		client.lastAccess = time.Now()

		if !client.limiter.Allow() {
			logger.Warn(r.Context(), "Rate limit exceeded",
				"clientIP", clientIP,
				"requestsPerSecond", rl.config.RequestsPerSecond,
				"burstSize", rl.config.BurstSize)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		logger.Debug(r.Context(), "Request allowed", "clientIP", clientIP)
		next.ServeHTTP(w, r)
	})
}

// cleanupLoop periodically removes old client limiters
func (rl *rateLimiter) cleanupLoop() {
	logger.Info(context.Background(), "Starting rate limiter cleanup loop",
		"interval", time.Minute)

	for {
		select {
		case <-rl.done:
			logger.Info(context.Background(), "Stopping rate limiter cleanup loop")
			return
		case <-rl.cleanup.C:
			rl.performCleanup()
		}
	}
}

// performCleanup removes expired client entries
func (rl *rateLimiter) performCleanup() {
	logger.Debug(context.Background(), "Starting rate limiter cleanup")

	now := time.Now()
	expiredCount := 0

	rl.clients.Range(func(key, value interface{}) bool {
		clientIP := key.(string)
		client := value.(*clientInfo)

		// Check if client has expired
		if now.Sub(client.lastAccess) > rl.config.ClientTimeout {
			rl.clients.Delete(key)
			expiredCount++
			logger.Debug(context.Background(), "Removed expired client",
				"clientIP", clientIP,
				"lastAccess", client.lastAccess)
		}
		return true
	})

	if expiredCount > 0 {
		logger.Info(context.Background(), "Completed rate limiter cleanup",
			"removedClients", expiredCount)
	} else {
		logger.Debug(context.Background(), "Completed rate limiter cleanup",
			"removedClients", 0)
	}
}

// Stop cleanly stops the rate limiter
func (rl *rateLimiter) Stop() {
	logger.Info(context.Background(), "Stopping rate limiter")
	close(rl.done)
	rl.cleanup.Stop()

	// Clear all clients
	clientCount := 0
	rl.clients.Range(func(key, value interface{}) bool {
		rl.clients.Delete(key)
		clientCount++
		return true
	})

	logger.Info(context.Background(), "Rate limiter stopped",
		"clearedClients", clientCount)
}
