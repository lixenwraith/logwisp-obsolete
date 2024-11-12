// File: logwisp/src/internal/monitor/file_watcher.go

package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"logwisp/src/internal/transport"

	"github.com/LixenWraith/logger"
)

// fileWatcher implements watching of a single file
type fileWatcher struct {
	*baseWatcher
}

// newFileWatcher creates a new file watcher instance
func newFileWatcher(base *baseWatcher) *fileWatcher {
	return &fileWatcher{
		baseWatcher: base,
	}
}

// watch implements the file monitoring loop
func (w *fileWatcher) watch(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.done:
			return nil
		case <-ticker.C:
			if err := w.checkFile(ctx); err != nil {
				logger.Error(ctx, "Error checking file",
					"path", w.targetPath,
					"error", err)
			}
		}
	}
}

// checkFile checks and processes the monitored file
func (w *fileWatcher) checkFile(ctx context.Context) error {
	// Get file info
	info, err := os.Stat(w.targetPath)
	if err != nil {
		return fmt.Errorf("stat error: %w", err)
	}

	// Check if file has been modified
	if !w.isModified(w.targetPath, info) {
		return nil
	}

	// Process file content
	if err := w.processFile(ctx); err != nil {
		return fmt.Errorf("processing error: %w", err)
	}

	return nil
}

// processFile reads and processes new content from the file
func (w *fileWatcher) processFile(ctx context.Context) error {
	info, err := os.Stat(w.targetPath)
	if err != nil {
		return fmt.Errorf("stat error: %w", err)
	}

	// Open file for reading
	file, err := os.Open(w.targetPath)
	if err != nil {
		return fmt.Errorf("open error: %w", err)
	}
	defer file.Close()

	// Get or create state
	w.mu.Lock()
	state := w.states.getOrCreate(w.targetPath, info)
	w.mu.Unlock()

	// Check for rotation
	if w.checkRotation(w.targetPath, info) {
		logger.Info(ctx, "File rotation detected, resetting position",
			"path", filepath.Base(w.targetPath))
		state.position = 0
	}

	// Seek to last position
	if _, err := file.Seek(state.position, io.SeekStart); err != nil {
		return fmt.Errorf("seek error: %w", err)
	}

	// Read new lines
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line size

	var linesProcessed int
	for scanner.Scan() {
		if w.isDone(ctx) {
			return nil
		}

		if err := w.processLine(ctx, scanner.Text()); err != nil {
			logger.Error(ctx, "Error processing line",
				"path", filepath.Base(w.targetPath),
				"error", err)
			continue
		}
		linesProcessed++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	// Update file state
	pos, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("position error: %w", err)
	}

	w.updateState(w.targetPath, pos, info)

	logger.Debug(ctx, "File processing complete",
		"path", filepath.Base(w.targetPath),
		"linesProcessed", linesProcessed)

	return nil
}

// processLine parses and sends a log line
func (w *fileWatcher) processLine(ctx context.Context, line string) error {
	// Try parsing as JSON first
	var jsonLog struct {
		Time    string          `json:"time"`
		Level   string          `json:"level"`
		Message string          `json:"msg"`
		Fields  json.RawMessage `json:"fields,omitempty"`
	}

	source := filepath.Base(w.targetPath)

	if err := json.Unmarshal([]byte(line), &jsonLog); err == nil {
		// Parse timestamp
		timestamp, err := time.Parse(time.RFC3339Nano, jsonLog.Time)
		if err != nil {
			logger.Warn(ctx, "Invalid timestamp in JSON log, using current time",
				"source", source,
				"time", jsonLog.Time)
			timestamp = time.Now()
		}

		// Create log entry
		entry := transport.LogEntry{
			Time:    timestamp,
			Level:   jsonLog.Level,
			Message: jsonLog.Message,
			Fields:  jsonLog.Fields,
			Source:  source,
		}

		w.callback(entry)
		return nil
	}

	// If not JSON, treat as plain text
	logger.Debug(ctx, "Processing plain text log line", "source", source)
	entry := transport.LogEntry{
		Time:    time.Now(),
		Level:   "INFO",
		Message: line,
		Source:  source,
	}

	w.callback(entry)
	return nil
}
