// File: logwisp/src/internal/monitor/monitor.go

package monitor

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"logwisp/src/internal/transport"

	"github.com/LixenWraith/logger"
)

// MonitorTarget defines a path to be monitored
type MonitorTarget interface {
	Path() string
	IsFile() bool
	Pattern() string // empty for files
}

// target implements MonitorTarget
type target struct {
	path    string
	isFile  bool
	pattern string
}

func (t *target) Path() string    { return t.path }
func (t *target) IsFile() bool    { return t.isFile }
func (t *target) Pattern() string { return t.pattern }

// NewTarget creates a new monitoring target
func NewTarget(path string, isFile bool, pattern string) MonitorTarget {
	if !isFile && pattern == "" {
		pattern = "*.log" // Default pattern for directories
	}
	return &target{
		path:    path,
		isFile:  isFile,
		pattern: pattern,
	}
}

// Monitor defines the monitoring system interface
type Monitor interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	AddTarget(target MonitorTarget) error
}

// FileSystemMonitor implements the Monitor interface
type FileSystemMonitor struct {
	callback    func(transport.LogEntry)
	targets     map[string]MonitorTarget
	watchers    map[string]watcher
	mu          sync.RWMutex
	done        chan struct{}
	checkPeriod time.Duration
	stats       monitorStats
}

// monitorStats tracks monitoring statistics
type monitorStats struct {
	activeWatchers  int64
	droppedEntries  int64
	processedFiles  int64
	lastCleanupTime time.Time
	mu              sync.RWMutex
}

// Config holds monitor configuration
type Config struct {
	// CheckPeriod is how often to check for file existence/changes
	CheckPeriod time.Duration
}

// NewMonitor creates a new FileSystemMonitor
func NewMonitor(callback func(transport.LogEntry), cfg *Config) *FileSystemMonitor {
	logger.Info(context.Background(), "Creating new file system monitor")

	if cfg == nil {
		cfg = &Config{
			CheckPeriod: 100 * time.Millisecond,
		}
		logger.Warn(context.Background(), "No config provided, using defaults",
			"checkPeriod", cfg.CheckPeriod)
	}

	m := &FileSystemMonitor{
		callback:    callback,
		targets:     make(map[string]MonitorTarget),
		watchers:    make(map[string]watcher),
		done:        make(chan struct{}),
		checkPeriod: cfg.CheckPeriod,
	}

	m.stats.lastCleanupTime = time.Now()

	logger.Info(context.Background(), "File system monitor created",
		"checkPeriod", cfg.CheckPeriod)

	return m
}

// AddTarget adds a new target to monitor
func (m *FileSystemMonitor) AddTarget(target MonitorTarget) error {
	if target == nil {
		return fmt.Errorf("target cannot be nil")
	}

	path := target.Path()
	if path == "" {
		return fmt.Errorf("target path cannot be empty")
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		logger.Error(context.Background(), "Invalid path",
			"path", path,
			"error", err)
		return fmt.Errorf("invalid path %s: %w", path, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate
	if _, exists := m.targets[absPath]; exists {
		logger.Warn(context.Background(), "Target already exists",
			"path", absPath)
		return fmt.Errorf("target already exists: %s", absPath)
	}

	m.targets[absPath] = target
	logger.Info(context.Background(), "Added monitoring target",
		"path", absPath,
		"isFile", target.IsFile(),
		"pattern", target.Pattern())

	return nil
}

// Start begins monitoring all targets
func (m *FileSystemMonitor) Start(ctx context.Context) error {
	logger.Info(ctx, "Starting file system monitor")

	m.mu.Lock()
	defer m.mu.Unlock()

	// Start watchers for all targets
	startedCount := 0
	for _, target := range m.targets {
		if err := m.startWatcher(ctx, target); err != nil {
			logger.Error(ctx, "Failed to start watcher",
				"path", target.Path(),
				"error", err)
			continue
		}
		startedCount++
	}

	logger.Info(ctx, "Started watchers",
		"total", len(m.targets),
		"successful", startedCount)

	// Start periodic check for new files
	go m.periodicCheck(ctx)

	return nil
}

// Stop halts all monitoring
func (m *FileSystemMonitor) Stop(ctx context.Context) error {
	logger.Info(ctx, "Stopping file system monitor")

	close(m.done)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop all watchers
	stoppedCount := 0
	for path, w := range m.watchers {
		w.stop()
		delete(m.watchers, path)
		stoppedCount++
		logger.Debug(ctx, "Stopped watcher",
			"path", path)
	}

	m.logFinalStats(ctx)

	logger.Info(ctx, "File system monitor stopped",
		"watchersStopped", stoppedCount)

	return nil
}

// startWatcher creates and starts a watcher for a target
func (m *FileSystemMonitor) startWatcher(ctx context.Context, target MonitorTarget) error {
	absPath, err := filepath.Abs(target.Path())
	if err != nil {
		return fmt.Errorf("invalid path %s: %w", target.Path(), err)
	}

	logger.Debug(ctx, "Creating watcher",
		"path", absPath,
		"isFile", target.IsFile())

	w := newBaseWatcher(absPath, m.handleLogEntry)

	// Verify path exists
	if !w.isAvailable() {
		return fmt.Errorf("path not available: %s", absPath)
	}

	var monitorInstance watcher
	if target.IsFile() {
		monitorInstance = newFileWatcher(w)
		logger.Debug(ctx, "Created file watcher", "path", absPath)
	} else {
		monitorInstance = newFolderWatcher(w, target.Pattern())
		logger.Debug(ctx, "Created folder watcher",
			"path", absPath,
			"pattern", target.Pattern())
	}

	m.watchers[absPath] = monitorInstance

	// Start the watcher in a goroutine
	go func() {
		if err := monitorInstance.watch(ctx); err != nil {
			logger.Error(ctx, "Watcher error",
				"path", absPath,
				"error", err)
			m.handleWatcherError(ctx, absPath)
		}
	}()

	m.stats.mu.Lock()
	m.stats.activeWatchers++
	m.stats.mu.Unlock()

	logger.Info(ctx, "Started watcher",
		"path", absPath,
		"isFile", target.IsFile())

	return nil
}

// handleLogEntry processes a log entry and updates statistics
func (m *FileSystemMonitor) handleLogEntry(entry transport.LogEntry) {
	m.callback(entry)

	m.stats.mu.Lock()
	m.stats.processedFiles++
	m.stats.mu.Unlock()
}

// handleWatcherError handles watcher failures and attempts recovery
func (m *FileSystemMonitor) handleWatcherError(ctx context.Context, path string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove failed watcher
	if w, exists := m.watchers[path]; exists {
		w.stop()
		delete(m.watchers, path)

		m.stats.mu.Lock()
		m.stats.activeWatchers--
		m.stats.mu.Unlock()

		logger.Warn(ctx, "Removed failed watcher", "path", path)
	}
}

// periodicCheck regularly checks for existence of monitored paths
func (m *FileSystemMonitor) periodicCheck(ctx context.Context) {
	logger.Debug(ctx, "Starting periodic check loop")

	ticker := time.NewTicker(m.checkPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Debug(ctx, "Context cancelled, stopping periodic check")
			return
		case <-m.done:
			logger.Debug(ctx, "Monitor stopped, stopping periodic check")
			return
		case <-ticker.C:
			m.checkTargets(ctx)
		}
	}
}

// checkTargets verifies all targets and starts watchers for newly available ones
func (m *FileSystemMonitor) checkTargets(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	recoveredCount := 0
	for path, target := range m.targets {
		// Skip if watcher already exists
		if _, exists := m.watchers[path]; exists {
			continue
		}

		// Try to start watcher
		if err := m.startWatcher(ctx, target); err != nil {
			logger.Debug(ctx, "Target not yet available",
				"path", path,
				"error", err)
			continue
		}

		recoveredCount++
		logger.Info(ctx, "Started delayed watcher",
			"path", path,
			"isFile", target.IsFile())
	}

	if recoveredCount > 0 {
		logger.Info(ctx, "Recovered watchers",
			"count", recoveredCount)
	}
}

// logFinalStats logs the final statistics when stopping
func (m *FileSystemMonitor) logFinalStats(ctx context.Context) {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	logger.Info(ctx, "Monitor final statistics",
		"processedFiles", m.stats.processedFiles,
		"droppedEntries", m.stats.droppedEntries,
		"activeWatchers", m.stats.activeWatchers,
		"uptime", time.Since(m.stats.lastCleanupTime))
}
