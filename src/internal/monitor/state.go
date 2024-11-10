// File: logwisp/src/internal/monitor/state.go

package monitor

import (
	"os"
	"time"
)

// watcherState tracks the state of a monitored path
type watcherState struct {
	path     string
	position int64
	lastMod  time.Time
}

// stateManager handles state operations for watchers
type stateManager struct {
	states map[string]*watcherState
}

// newStateManager creates a new state manager
func newStateManager() *stateManager {
	return &stateManager{
		states: make(map[string]*watcherState),
	}
}

// getOrCreate returns existing state or creates new one
func (sm *stateManager) getOrCreate(path string, info os.FileInfo) *watcherState {
	state, exists := sm.states[path]
	if !exists {
		state = &watcherState{
			path:     path,
			position: 0,
			lastMod:  info.ModTime(),
		}
		sm.states[path] = state
	}
	return state
}

// update updates the state with new position and modification time
func (sm *stateManager) update(path string, position int64, modTime time.Time) {
	if state, exists := sm.states[path]; exists {
		state.position = position
		state.lastMod = modTime
	}
}

// reset resets the state for a path
func (sm *stateManager) reset(path string) {
	if state, exists := sm.states[path]; exists {
		state.position = 0
	}
}

// remove removes state for a path
func (sm *stateManager) remove(path string) {
	delete(sm.states, path)
}

// hasModified checks if file has been modified since last check
func (sm *stateManager) hasModified(path string, info os.FileInfo) bool {
	state, exists := sm.states[path]
	if !exists {
		return true
	}
	return info.ModTime().After(state.lastMod)
}

// wasRotated checks if file has been rotated
func (sm *stateManager) wasRotated(path string, info os.FileInfo) bool {
	state, exists := sm.states[path]
	if !exists {
		return false
	}
	return info.Size() < state.position
}

// cleanup removes states for non-existent paths
func (sm *stateManager) cleanup() {
	for path := range sm.states {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			delete(sm.states, path)
		}
	}
}
