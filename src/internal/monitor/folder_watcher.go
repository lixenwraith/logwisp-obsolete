// File: logwisp/src/internal/monitor/folder_watcher.go

package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"logwisp/src/pkg/logger"
)

// folderWatcher implements watching of a directory
type folderWatcher struct {
	*baseWatcher
	pattern string
}

// newFolderWatcher creates a new directory watcher instance
func newFolderWatcher(base *baseWatcher, pattern string) *folderWatcher {
	if pattern == "" {
		pattern = "*.log" // Default pattern
	}
	return &folderWatcher{
		baseWatcher: base,
		pattern:     pattern,
	}
}

// watch implements the directory monitoring loop
func (w *folderWatcher) watch(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-w.done:
			return nil
		case <-ticker.C:
			if err := w.checkFolder(ctx); err != nil {
				logger.Error(ctx, "Error checking directory",
					"path", w.targetPath,
					"error", err)
			}
		}
	}
}

// checkFolder scans the directory for matching files
func (w *folderWatcher) checkFolder(ctx context.Context) error {
	// Clean up states for deleted files periodically
	w.cleanupStates()

	// Find all matching files
	matches, err := filepath.Glob(filepath.Join(w.targetPath, w.pattern))
	if err != nil {
		return fmt.Errorf("glob pattern error: %w", err)
	}

	// Process each matching file
	for _, path := range matches {
		if w.isDone(ctx) {
			return nil
		}

		// Create a file watcher for this file
		fw := &fileWatcher{
			baseWatcher: &baseWatcher{
				targetPath: path,
				callback:   w.callback,
				done:       w.done,   // Share the done channel
				states:     w.states, // Share the state manager
				mu:         w.mu,     // Share the mutex
			},
		}

		if err := fw.checkFile(ctx); err != nil {
			logger.Error(ctx, "Error processing file",
				"path", path,
				"error", err)
			continue
		}
	}

	return nil
}

// isAvailable checks if the directory exists and is accessible
func (w *folderWatcher) isAvailable() bool {
	info, err := w.getDirectoryInfo()
	if err != nil {
		return false
	}
	return info.IsDir()
}

// getDirectoryInfo gets directory information
func (w *folderWatcher) getDirectoryInfo() (os.FileInfo, error) {
	info, err := os.Stat(w.targetPath)
	if err != nil {
		return nil, fmt.Errorf("stat error: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", w.targetPath)
	}
	return info, nil
}

// validatePattern checks if the glob pattern is valid
func (w *folderWatcher) validatePattern() error {
	if w.pattern == "" {
		return fmt.Errorf("empty pattern")
	}
	// Test pattern compilation
	_, err := filepath.Match(w.pattern, "test.log")
	if err != nil {
		return fmt.Errorf("invalid pattern %s: %w", w.pattern, err)
	}
	return nil
}

// String returns a string representation of the folder watcher
func (w *folderWatcher) String() string {
	return fmt.Sprintf("FolderWatcher{path: %s, pattern: %s}", w.targetPath, w.pattern)
}
