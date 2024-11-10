// File: logwisp/src/internal/viewer/viewer.go

package viewer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/transport"
	"logwisp/src/pkg/logger"
)

// ANSI color codes remain unchanged
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
)

// reconnectConfig holds reconnection parameters
type reconnectConfig struct {
	initialDelay  time.Duration
	maxDelay      time.Duration
	backoffFactor float64
}

// Viewer represents the log viewing client
type Viewer struct {
	cfg           *config.Config
	client        *http.Client
	url           string
	done          chan struct{}
	closeOnce     sync.Once
	reconnectCfg  reconnectConfig
	shouldRestart chan struct{}
}

// New creates a new viewer instance
func New(cfg *config.Config) (*Viewer, error) {
	logger.Info(context.Background(), "Creating new viewer instance")

	// Create HTTP client with optional TLS
	client := &http.Client{
		Timeout: 5 * time.Second, // Timeout for initial connection
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // TODO: Implement proper certificate verification
			},
			ResponseHeaderTimeout: 5 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
	}

	// Construct service URL
	scheme := "http"
	if cfg.Security.TLSEnabled {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://localhost:%d/stream", scheme, cfg.Port)

	logger.Info(context.Background(), "Viewer instance created",
		"url", url,
		"tls", cfg.Security.TLSEnabled)

	return &Viewer{
		cfg:    cfg,
		client: client,
		url:    url,
		done:   make(chan struct{}),
		reconnectCfg: reconnectConfig{
			initialDelay:  time.Second,
			maxDelay:      time.Minute,
			backoffFactor: 2,
		},
		shouldRestart: make(chan struct{}, 1),
	}, nil
}

// Start begins the log viewing session
func (v *Viewer) Start(ctx context.Context) error {
	logger.Info(ctx, "Starting viewer")

	// Prepare terminal
	if err := v.setupTerminal(); err != nil {
		logger.Error(ctx, "Terminal setup failed", "error", err)
		return fmt.Errorf("terminal setup error: %w", err)
	}

	// Start connection management loop
	go v.connectionLoop(ctx)

	// Handle user input for quit
	go v.handleUserInput(ctx)

	logger.Info(ctx, "Viewer started successfully")
	return nil
}

// connectionLoop manages the connection lifecycle
func (v *Viewer) connectionLoop(ctx context.Context) {
	logger.Debug(ctx, "Starting connection management loop")

	delay := v.reconnectCfg.initialDelay
	attemptCount := 0

	for {
		select {
		case <-ctx.Done():
			logger.Debug(ctx, "Context cancelled, stopping connection loop")
			return
		case <-v.done:
			logger.Debug(ctx, "Viewer stopped, stopping connection loop")
			return
		default:
			logger.Debug(ctx, "Attempting connection",
				"attempt", attemptCount+1,
				"delay", delay)

			if err := v.connect(ctx); err != nil {
				logger.Error(ctx, "Connection failed",
					"attempt", attemptCount+1,
					"error", err)

				// Calculate next delay
				delay = time.Duration(float64(delay) * v.reconnectCfg.backoffFactor)
				if delay > v.reconnectCfg.maxDelay {
					delay = v.reconnectCfg.maxDelay
				}

				attemptCount++

				// Wait before reconnecting
				select {
				case <-time.After(delay):
					continue
				case <-ctx.Done():
					return
				case <-v.done:
					return
				}
			}

			// Reset counters on successful connection
			delay = v.reconnectCfg.initialDelay
			attemptCount = 0

			// Wait for reconnection signal
			select {
			case <-v.shouldRestart:
				logger.Info(ctx, "Reconnection requested")
				continue
			case <-ctx.Done():
				return
			case <-v.done:
				return
			}
		}
	}
}

// connect establishes a connection to the service
func (v *Viewer) connect(ctx context.Context) error {
	logger.Debug(ctx, "Creating new connection request")

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", v.url, nil)
	if err != nil {
		return fmt.Errorf("request creation error: %w", err)
	}

	// Add authentication if enabled
	if v.cfg.Security.AuthEnabled {
		req.SetBasicAuth(v.cfg.Security.AuthUsername, v.cfg.Security.AuthPassword)
		logger.Debug(ctx, "Added authentication credentials to request")
	}

	// Connect to service
	logger.Debug(ctx, "Connecting to service", "url", v.url)
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("server returned error: %s", resp.Status)
	}

	logger.Info(ctx, "Successfully connected to service")

	// Start processing events
	go v.processEvents(ctx, resp.Body)

	return nil
}

// handleUserInput processes user commands
func (v *Viewer) handleUserInput(ctx context.Context) {
	logger.Debug(ctx, "Starting user input handler")

	reader := bufio.NewReader(os.Stdin)
	for {
		char, err := reader.ReadByte()
		if err != nil {
			logger.Warn(ctx, "Error reading user input", "error", err)
			continue
		}

		if char == 'q' || char == 'Q' {
			logger.Info(ctx, "Quit command received")
			v.Stop(ctx)
			return
		}
	}
}

// Stop gracefully shuts down the viewer
func (v *Viewer) Stop(ctx context.Context) error {
	logger.Info(ctx, "Stopping viewer")

	v.closeOnce.Do(func() {
		close(v.done)
	})
	v.restoreTerminal()

	logger.Info(ctx, "Viewer stopped")
	return nil
}

// setupTerminal remains unchanged but adds logging
func (v *Viewer) setupTerminal() error {
	logger.Debug(context.Background(), "Setting up terminal")
	// Hide cursor
	fmt.Print("\033[?25l")
	// Clear screen
	fmt.Print("\033[2J")
	// Move cursor to top
	fmt.Print("\033[H")
	// Print header
	fmt.Printf("%sLogWisp Viewer - Connected to %s%s\n\n",
		colorCyan, v.url, colorReset)
	return nil
}

// restoreTerminal remains unchanged but adds logging
func (v *Viewer) restoreTerminal() {
	logger.Debug(context.Background(), "Restoring terminal")
	fmt.Print("\033[?25h") // Show cursor
	fmt.Print("\033[J")    // Clear to bottom
}

// processEvents handles the SSE stream
func (v *Viewer) processEvents(ctx context.Context, reader io.ReadCloser) {
	logger.Debug(ctx, "Starting event processing")
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Split(splitSSE)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			logger.Debug(ctx, "Context cancelled, stopping event processing")
			return
		case <-v.done:
			logger.Debug(ctx, "Viewer stopped, stopping event processing")
			return
		default:
			data := scanner.Text()
			if strings.HasPrefix(data, ":") {
				logger.Debug(ctx, "Received heartbeat")
				continue // Skip heartbeat
			}

			if err := v.handleEvent(data); err != nil {
				logger.Error(ctx, "Error handling event",
					"error", err,
					"data", data)
				// Signal reconnection
				select {
				case v.shouldRestart <- struct{}{}:
					logger.Info(ctx, "Reconnection signaled due to event handling error")
				default:
					logger.Debug(ctx, "Reconnection already pending")
				}
				return
			}
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error(ctx, "Stream error", "error", err)
		// Signal reconnection
		select {
		case v.shouldRestart <- struct{}{}:
			logger.Info(ctx, "Reconnection signaled due to stream error")
		default:
			logger.Debug(ctx, "Reconnection already pending")
		}
	}
}

// handleEvent processes and displays a log event
func (v *Viewer) handleEvent(data string) error {
	var entry transport.LogEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		return fmt.Errorf("json decode error: %w", err)
	}

	// Format timestamp
	timestamp := entry.Time.Format("15:04:05.000")

	// Choose color based on log level
	levelColor := v.getLevelColor(entry.Level)

	// Format and print log line
	fmt.Printf("%s%s%s %s%-5s%s %s%s%s %s%s%s %s\n",
		colorMagenta, timestamp, colorReset,
		levelColor, strings.ToUpper(entry.Level), colorReset,
		colorCyan, entry.Source, colorReset,
		colorReset, entry.Message, colorReset,
		v.formatFields(entry.Fields))

	return nil
}

// getLevelColor returns the appropriate color for a log level
func (v *Viewer) getLevelColor(level string) string {
	switch strings.ToUpper(level) {
	case "ERROR":
		return colorRed
	case "WARN":
		return colorYellow
	case "DEBUG":
		return colorBlue
	default:
		return colorGreen
	}
}

// formatFields formats additional fields for display
func (v *Viewer) formatFields(fields json.RawMessage) string {
	if len(fields) == 0 {
		return ""
	}

	var m map[string]interface{}
	if err := json.Unmarshal(fields, &m); err != nil {
		logger.Warn(context.Background(), "Failed to parse log fields", "error", err)
		return ""
	}

	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s%s=%v%s",
			colorCyan, k, v, colorReset))
	}

	if len(parts) > 0 {
		return fmt.Sprintf(" [%s]", strings.Join(parts, " "))
	}

	return ""
}

// splitSSE splits Server-Sent Events stream into individual events
func splitSSE(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := strings.Index(string(data), "\n\n"); i >= 0 {
		// Extract event data
		event := make([]byte, i)
		copy(event, data[:i])
		return i + 2, event, nil
	}

	if atEOF {
		return len(data), data, nil
	}

	return 0, nil, nil
}
