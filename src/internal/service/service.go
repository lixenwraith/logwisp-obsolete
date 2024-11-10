// File: logwisp/src/internal/service/service.go

package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/middleware"
	"logwisp/src/internal/monitor"
	"logwisp/src/internal/transport"
	"logwisp/src/pkg/logger"
)

// Service represents the log monitoring and streaming service
type Service struct {
	cfg          *config.Config
	server       *http.Server
	streamServer *transport.StreamServer
	monitor      monitor.Monitor
	done         chan struct{}
	middlewares  []middleware.Middleware
	cleanups     []middleware.Cleanup
	connPool     *connectionPool
}

// connectionPool manages a pool of idle connections
type connectionPool struct {
	maxIdle     int
	idleTimeout time.Duration
	mu          sync.RWMutex
	idle        []*poolConn
	active      map[*poolConn]struct{}
}

// poolConn wraps a network connection with metadata
type poolConn struct {
	net.Conn
	pool      *connectionPool
	lastUsed  time.Time
	inUse     bool
	closeOnce sync.Once
}

// New creates a new service instance
func New(cfg *config.Config) (*Service, error) {
	logger.Info(context.Background(), "Creating new service instance")

	streamServer := transport.NewStreamServer(
		cfg.Stream.BufferSize,
	)

	monitorCfg := &monitor.Config{
		CheckPeriod: time.Duration(cfg.Monitor.CheckPeriod) * time.Millisecond,
	}

	// Create adapter function to match signatures
	publishAdapter := func(entry transport.LogEntry) {
		streamServer.Publish(context.Background(), entry)
	}

	fsMonitor := monitor.NewMonitor(publishAdapter, monitorCfg)

	// Create rate limiter
	rateLimitMiddleware, rateLimitCleanup := middleware.NewRateLimiter(middleware.RateLimiterConfig{
		RequestsPerSecond: float64(cfg.Stream.RateLimit.RequestsPerSecond),
		BurstSize:         cfg.Stream.RateLimit.BurstSize,
		ClientTimeout:     time.Duration(cfg.Stream.RateLimit.ClientTimeoutMinutes) * time.Minute,
	})

	// Initialize connection pool
	pool := &connectionPool{
		maxIdle:     10, // Configurable if needed
		idleTimeout: 5 * time.Minute,
		active:      make(map[*poolConn]struct{}),
	}

	s := &Service{
		cfg:          cfg,
		streamServer: streamServer,
		monitor:      fsMonitor,
		done:         make(chan struct{}),
		middlewares:  []middleware.Middleware{rateLimitMiddleware},
		cleanups:     []middleware.Cleanup{rateLimitCleanup},
		connPool:     pool,
	}

	// Create HTTP server with custom connection handling
	mux := http.NewServeMux()

	// Apply middleware chain to stream handler
	handler := s.authMiddleware(streamServer)
	for _, m := range s.middlewares {
		handler = m(handler)
	}
	mux.Handle("/stream", handler)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
		ConnState: func(conn net.Conn, state http.ConnState) {
			s.handleConnState(conn, state)
		},
	}

	logger.Info(context.Background(), "Service instance created",
		"port", cfg.Port,
		"bufferSize", cfg.Stream.BufferSize)

	return s, nil
}

// handleConnState manages connection lifecycle
func (s *Service) handleConnState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		logger.Debug(context.Background(), "New connection",
			"remote", conn.RemoteAddr().String())

	case http.StateActive:
		if pc, ok := conn.(*poolConn); ok {
			s.connPool.markActive(pc)
		}
		logger.Debug(context.Background(), "Connection active",
			"remote", conn.RemoteAddr().String())

	case http.StateIdle:
		if pc, ok := conn.(*poolConn); ok {
			s.connPool.markIdle(pc)
		}
		logger.Debug(context.Background(), "Connection idle",
			"remote", conn.RemoteAddr().String())

	case http.StateClosed:
		if pc, ok := conn.(*poolConn); ok {
			s.connPool.remove(pc)
		}
		logger.Debug(context.Background(), "Connection closed",
			"remote", conn.RemoteAddr().String())
	}
}

// Start begins the service operation
func (s *Service) Start(ctx context.Context) error {
	logger.Info(ctx, "Starting service")

	// Add all targets to monitor
	for _, target := range s.cfg.GetMonitorTargets() {
		monitorTarget := monitor.NewTarget(target.Path, target.IsFile, target.Pattern)
		if err := s.monitor.AddTarget(monitorTarget); err != nil {
			logger.Error(ctx, "Failed to add monitor target",
				"path", target.Path,
				"error", err)
			continue
		}
	}

	// Start the monitor
	if err := s.monitor.Start(ctx); err != nil {
		logger.Error(ctx, "Failed to start monitor", "error", err)
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	// Start connection pool cleanup
	go s.connPool.cleanup(ctx)

	// Start HTTP server
	go func() {
		var err error
		if s.cfg.Security.TLSEnabled {
			logger.Info(ctx, "Starting HTTPS server",
				"cert", s.cfg.Security.TLSCertFile,
				"key", s.cfg.Security.TLSKeyFile)
			err = s.server.ListenAndServeTLS(
				s.cfg.Security.TLSCertFile,
				s.cfg.Security.TLSKeyFile,
			)
		} else {
			logger.Info(ctx, "Starting HTTP server")
			err = s.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error(ctx, "HTTP server error", "error", err)
			close(s.done)
		}
	}()

	logger.Info(ctx, "Service started",
		"port", s.cfg.Port,
		"tls", s.cfg.Security.TLSEnabled,
		"monitorTargets", len(s.cfg.Monitor.Paths))

	return nil
}

// Stop gracefully shuts down the service
func (s *Service) Stop(ctx context.Context) error {
	logger.Info(ctx, "Stopping service")

	// Stop monitor
	if err := s.monitor.Stop(ctx); err != nil {
		logger.Error(ctx, "Error stopping monitor", "error", err)
	}

	// Stop stream server
	if err := s.streamServer.Stop(ctx); err != nil {
		logger.Error(ctx, "Error stopping stream server", "error", err)
	}

	// Cleanup middlewares
	for _, cleanup := range s.cleanups {
		cleanup.Stop()
	}

	// Close all connections in the pool
	s.connPool.closeAll()

	// Shutdown HTTP server
	if err := s.server.Shutdown(ctx); err != nil {
		logger.Error(ctx, "Error shutting down HTTP server", "error", err)
		return fmt.Errorf("error shutting down HTTP server: %w", err)
	}

	logger.Info(ctx, "Service stopped successfully")
	return nil
}

// Connection Pool methods

func (p *connectionPool) get() *poolConn {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to reuse an idle connection
	for i := len(p.idle) - 1; i >= 0; i-- {
		conn := p.idle[i]
		p.idle = p.idle[:i]
		if time.Since(conn.lastUsed) > p.idleTimeout {
			conn.closeOnce.Do(func() {
				conn.Close()
			})
			continue
		}
		conn.inUse = true
		p.active[conn] = struct{}{}
		return conn
	}
	return nil
}

func (p *connectionPool) markActive(conn *poolConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conn.inUse = true
	p.active[conn] = struct{}{}
}

func (p *connectionPool) markIdle(conn *poolConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.active, conn)
	conn.inUse = false
	conn.lastUsed = time.Now()

	if len(p.idle) < p.maxIdle {
		p.idle = append(p.idle, conn)
	} else {
		conn.closeOnce.Do(func() {
			conn.Close()
		})
	}
}

func (p *connectionPool) remove(conn *poolConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.active, conn)
}

func (p *connectionPool) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.mu.Lock()
			deadline := time.Now().Add(-p.idleTimeout)
			remaining := make([]*poolConn, 0, len(p.idle))

			for _, conn := range p.idle {
				if conn.lastUsed.Before(deadline) {
					conn.closeOnce.Do(func() {
						conn.Close()
					})
				} else {
					remaining = append(remaining, conn)
				}
			}
			p.idle = remaining
			p.mu.Unlock()
		}
	}
}

func (p *connectionPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close idle connections
	for _, conn := range p.idle {
		conn.closeOnce.Do(func() {
			conn.Close()
		})
	}
	p.idle = nil

	// Close active connections
	for conn := range p.active {
		conn.closeOnce.Do(func() {
			conn.Close()
		})
		delete(p.active, conn)
	}
}

// authMiddleware implements basic authentication if enabled
func (s *Service) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Security.AuthEnabled {
			next.ServeHTTP(w, r)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != s.cfg.Security.AuthUsername || password != s.cfg.Security.AuthPassword {
			logger.Warn(r.Context(), "Unauthorized access attempt",
				"remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Basic realm="logwisp"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		logger.Debug(r.Context(), "Authenticated request",
			"username", username,
			"remote", r.RemoteAddr)

		next.ServeHTTP(w, r)
	})
}
