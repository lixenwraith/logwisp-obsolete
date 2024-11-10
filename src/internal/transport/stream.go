// File: logwisp/src/internal/transport/stream.go

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"logwisp/src/pkg/logger"
)

// LogEntry represents a single log message in the stream
type LogEntry struct {
	Time    time.Time       `json:"time"`
	Level   string          `json:"level"`
	Message string          `json:"msg"`
	Fields  json.RawMessage `json:"fields,omitempty"`
	Source  string          `json:"source"` // Log file source
}

// StreamServer handles Server-Sent Events streaming of logs
type StreamServer struct {
	clients    sync.Map      // map[string]*clientConnection
	buffer     chan LogEntry // Buffer for log entries
	bufferSize int           // Configuration
	stats      serverStats
}

// serverStats tracks streaming statistics
type serverStats struct {
	activeClients   int64
	totalMessages   int64
	droppedMessages int64
	reconnections   int64
	mu              sync.RWMutex
}

// clientConnection represents a connected client
type clientConnection struct {
	id           string
	messages     chan LogEntry
	done         chan struct{}
	lastActivity time.Time
	mu           sync.RWMutex
}

// NewStreamServer creates a new SSE streaming server
func NewStreamServer(bufferSize int) *StreamServer {
	logger.Info(context.Background(), "Creating new stream server")

	if bufferSize < 1 {
		bufferSize = 1000 // Default buffer size
		logger.Warn(context.Background(), "Invalid buffer size, using default",
			"size", bufferSize)
	}

	s := &StreamServer{
		buffer:     make(chan LogEntry, bufferSize),
		bufferSize: bufferSize,
	}

	logger.Info(context.Background(), "Stream server created",
		"bufferSize", bufferSize)
	return s
}

// ServeHTTP implements http.Handler for SSE streaming
func (s *StreamServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Debug(r.Context(), "New client connection attempt",
		"remoteAddr", r.RemoteAddr)

	// Verify request is GET
	if r.Method != http.MethodGet {
		logger.Warn(r.Context(), "Invalid request method",
			"method", r.Method,
			"remoteAddr", r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Create client connection
	client := &clientConnection{
		id:           fmt.Sprintf("%d", time.Now().UnixNano()),
		messages:     make(chan LogEntry, s.bufferSize),
		done:         make(chan struct{}),
		lastActivity: time.Now(),
	}

	// Store client
	s.clients.Store(client.id, client)
	s.incrementActiveClients()
	defer s.removeClient(client.id)

	logger.Info(r.Context(), "Client connected",
		"clientID", client.id,
		"remoteAddr", r.RemoteAddr)

	// Create heartbeat ticker
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Create inactivity checker
	inactivityCheck := time.NewTicker(1 * time.Minute)
	defer inactivityCheck.Stop()

	// Send initial connection message
	if err := s.writeEvent(w, map[string]string{
		"type":      "connected",
		"client_id": client.id,
	}); err != nil {
		logger.Error(r.Context(), "Failed to send connection message",
			"clientID", client.id,
			"error", err)
		return
	}

	// Start streaming
	for {
		select {
		case <-r.Context().Done():
			logger.Info(r.Context(), "Client request terminated",
				"clientID", client.id)
			return

		case <-client.done:
			logger.Info(r.Context(), "Client disconnected",
				"clientID", client.id)
			return

		case entry := <-client.messages:
			if err := s.writeEvent(w, entry); err != nil {
				logger.Error(r.Context(), "Failed to write log entry",
					"clientID", client.id,
					"error", err)
				return
			}
			client.updateActivity()
			s.incrementTotalMessages()

		case <-ticker.C:
			if err := s.writeHeartbeat(w); err != nil {
				logger.Error(r.Context(), "Failed to send heartbeat",
					"clientID", client.id,
					"error", err)
				return
			}
			client.updateActivity()

		case <-inactivityCheck.C:
			if client.isInactive(5 * time.Minute) {
				logger.Warn(r.Context(), "Client inactive, closing connection",
					"clientID", client.id)
				return
			}
		}
	}
}

// writeEvent writes an SSE event to the response writer
func (s *StreamServer) writeEvent(w http.ResponseWriter, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	if _, err := fmt.Fprintf(w, "data: %s\n\n", jsonData); err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	w.(http.Flusher).Flush()
	return nil
}

// writeHeartbeat sends a heartbeat message
func (s *StreamServer) writeHeartbeat(w http.ResponseWriter) error {
	if _, err := fmt.Fprintf(w, ": heartbeat\n\n"); err != nil {
		return fmt.Errorf("heartbeat error: %w", err)
	}
	w.(http.Flusher).Flush()
	return nil
}

// Publish adds a log entry to all client buffers
func (s *StreamServer) Publish(ctx context.Context, entry LogEntry) {
	var delivered, dropped int

	s.clients.Range(func(key, value interface{}) bool {
		client := value.(*clientConnection)
		select {
		case client.messages <- entry:
			delivered++
		default:
			dropped++
			logger.Warn(ctx, "Client buffer full, removing slow client",
				"clientID", client.id)
			s.removeClient(client.id)
			s.incrementDroppedMessages()
		}
		return true
	})

	if dropped > 0 {
		logger.Warn(ctx, "Some clients dropped due to full buffers",
			"delivered", delivered,
			"dropped", dropped)
	}

	logger.Debug(ctx, "Entry published",
		"delivered", delivered,
		"source", entry.Source)
}

// removeClient removes a client connection
func (s *StreamServer) removeClient(id string) {
	if client, ok := s.clients.LoadAndDelete(id); ok {
		c := client.(*clientConnection)
		close(c.done)
		close(c.messages)
		s.decrementActiveClients()
		logger.Debug(context.Background(), "Client removed", "clientID", id)
	}
}

// Stop gracefully shuts down the stream server
func (s *StreamServer) Stop(ctx context.Context) error {
	logger.Info(ctx, "Stopping stream server")

	// Remove all clients
	var count int
	s.clients.Range(func(key, value interface{}) bool {
		s.removeClient(key.(string))
		count++
		return true
	})

	s.logStats()
	logger.Info(ctx, "Stream server stopped", "clientsDisconnected", count)
	return nil
}

// Client activity methods
func (c *clientConnection) updateActivity() {
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()
}

func (c *clientConnection) isInactive(timeout time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.lastActivity) > timeout
}

// Statistics methods
func (s *StreamServer) incrementActiveClients() {
	s.stats.mu.Lock()
	s.stats.activeClients++
	s.stats.mu.Unlock()
}

func (s *StreamServer) decrementActiveClients() {
	s.stats.mu.Lock()
	s.stats.activeClients--
	s.stats.mu.Unlock()
}

func (s *StreamServer) incrementTotalMessages() {
	s.stats.mu.Lock()
	s.stats.totalMessages++
	s.stats.mu.Unlock()
}

func (s *StreamServer) incrementDroppedMessages() {
	s.stats.mu.Lock()
	s.stats.droppedMessages++
	s.stats.mu.Unlock()
}

func (s *StreamServer) logStats() {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	logger.Info(context.Background(), "Stream server statistics",
		"activeClients", s.stats.activeClients,
		"totalMessages", s.stats.totalMessages,
		"droppedMessages", s.stats.droppedMessages,
		"reconnections", s.stats.reconnections)
}
