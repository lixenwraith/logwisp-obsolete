// File: logwisp/src/internal/middleware/middleware.go

package middleware

import (
	"net/http"
)

// Middleware represents a chainable HTTP middleware function
type Middleware func(http.Handler) http.Handler

// Chain creates a new middleware chain from the given middlewares
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// Cleanup interface for middlewares that need cleanup
type Cleanup interface {
	Stop()
}

// Make sure rateLimiter implements Cleanup
var _ Cleanup = (*rateLimiter)(nil)
