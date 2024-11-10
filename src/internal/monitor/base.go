// File: logwisp/src/internal/monitor/base.go

package monitor

import (
	"context"
	"fmt"
	"os"
	"sync"

	"logwisp/src/internal/transport"
)

// watcher defines the interface for file and directory monitoring
type watcher interface {
	watch(ctx context.Context) error
	stop()
	isAvailable() bool
	path() string
}

// baseWatcher provides common functionality for both file and directory watchers
type baseWatcher struct {
	targetPath string
	callback   func(transport.LogEntry)
	done       chan struct{}
	states     *stateManager
	mu         sync.RWMutex
}

// newBaseWatcher creates a new base watcher instance
func newBaseWatcher(targetPath string, callback func(transport.LogEntry)) *baseWatcher {
	return &baseWatcher{
		targetPath: targetPath,
		callback:   callback,
		done:       make(chan struct{}),
		states:     newStateManager(),
	}
}

// watch implements the base watch method
func (w *baseWatcher) watch(ctx context.Context) error {
	return fmt.Errorf("watch not implemented for base watcher")
}

// stop stops the watcher
func (w *baseWatcher) stop() {
	select {
	case <-w.done:
		return
	default:
		close(w.done)
	}
}

// path returns the target path
func (w *baseWatcher) path() string {
	return w.targetPath
}

// isAvailable checks if the target path exists
func (w *baseWatcher) isAvailable() bool {
	_, err := os.Stat(w.targetPath)
	return err == nil
}

// isStopped checks if the watcher has been stopped
func (w *baseWatcher) isStopped() bool {
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// isDone checks if either context is done or watcher is stopped
func (w *baseWatcher) isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	case <-w.done:
		return true
	default:
		return false
	}
}

// isModified checks if a file has been modified
func (w *baseWatcher) isModified(path string, info os.FileInfo) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.states.hasModified(path, info)
}

// checkRotation checks for file rotation
func (w *baseWatcher) checkRotation(path string, info os.FileInfo) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.states.wasRotated(path, info)
}

// updateState updates the tracking state for a file
func (w *baseWatcher) updateState(path string, position int64, modTime os.FileInfo) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.states.update(path, position, modTime.ModTime())
}

// resetState resets tracking state for a file
func (w *baseWatcher) resetState(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.states.reset(path)
}

// removeState removes tracking state for a file
func (w *baseWatcher) removeState(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.states.remove(path)
}

// cleanupStates removes states for non-existent files
func (w *baseWatcher) cleanupStates() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.states.cleanup()
}
