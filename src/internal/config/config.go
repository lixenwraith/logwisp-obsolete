// File: logwisp/src/internal/config/config.go

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/LixenWraith/logger"
	"github.com/LixenWraith/tinytoml"
)

// OperationMode defines how logwisp will run
type OperationMode string

const (
	// ServiceMode runs as a background daemon streaming logs
	ServiceMode OperationMode = "service"
	// ViewerMode runs as an interactive terminal client
	ViewerMode OperationMode = "viewer"
)

// Validation constants
const (
	minPort           = 1024
	maxPort           = 65535
	minBufferSize     = 100
	defaultBufferSize = 1000
	minCheckPeriod    = 100 // milliseconds
	defaultPattern    = "*.log"
)

// Config holds the complete configuration for logwisp
type Config struct {
	mu sync.RWMutex // Protects config fields during reload

	// Mode determines whether to run as service or viewer
	Mode OperationMode `toml:"mode"`

	// Port defines the service listening port
	Port int `toml:"port"`

	// Logger configuration section
	Logger logger.LoggerConfig `toml:"logger"`

	// Security configuration section
	Security SecurityConfig `toml:"security"`

	// Monitor configuration
	Monitor MonitorConfig `toml:"monitor"`

	// Stream configuration
	Stream StreamConfig `toml:"stream"`
}

// SecurityConfig holds security settings for streaming
type SecurityConfig struct {
	TLSEnabled  bool   `toml:"tls_enabled"`
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`

	AuthEnabled  bool   `toml:"auth_enabled"`
	AuthUsername string `toml:"auth_username"`
	AuthPassword string `toml:"auth_password"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	RequestsPerSecond    int `toml:"requests_per_second"`
	BurstSize            int `toml:"burst_size"`
	ClientTimeoutMinutes int `toml:"client_timeout_minutes"`
}

// MonitorConfig hold the settings for paths to the monitored logs
type MonitorConfig struct {
	// Targets is a collection of monitored paths
	Paths       map[string]MonitorPath `toml:"paths"`
	CheckPeriod int                    `toml:"check_period_ms"`
}

// MonitorPath represents a path to be monitored
type MonitorPath struct {
	Path    string `toml:"path"`
	Pattern string `toml:"pattern"`
	IsFile  bool   `toml:"is_file"`
}

// StreamConfig holds the stream settings
type StreamConfig struct {
	BufferSize      int             `toml:"buffer_size"`
	FlushIntervalMs int             `toml:"flush_interval_ms"`
	RateLimit       RateLimitConfig `toml:"rate_limit"`
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Load implements a two-phase configuration loading:
// 1. Set program defaults
// 2. Override with file configuration if exists
func Load(configPath string) (*Config, error) {
	// Initialize with defaults
	cfg := new(Config)
	cfg.setDefaults()

	// Ensure configuration directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("creating config directory: %w", err)
	}

	// Check if configuration file exists
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}

		// Override defaults with file configuration
		if err := tinytoml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	// Ensure log directory exists
	if err := os.MkdirAll(cfg.Logger.Directory, 0755); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Reload reloads configuration from the same file
func (c *Config) Reload(configPath string) error {
	newCfg, err := Load(configPath)
	if err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Preserve runtime mode
	currentMode := c.Mode
	if newCfg.Mode != currentMode {
		return fmt.Errorf("cannot change mode during reload")
	}

	// Apply new configuration
	*c = *newCfg
	c.Mode = currentMode

	return nil
}

// GetMonitorTargets is reader method with mutex protection
func (c *Config) GetMonitorTargets() []MonitorTarget {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var targets []MonitorTarget
	for _, path := range c.Monitor.Paths {
		targets = append(targets, MonitorTarget{
			Path:    path.Path,
			Pattern: path.Pattern,
			IsFile:  path.IsFile,
		})
	}
	return targets
}

// setDefaults sets default values for optional fields
func (c *Config) setDefaults() {
	c.Mode = ServiceMode
	c.Port = 8080

	// Logger defaults
	c.Logger = logger.LoggerConfig{
		Level:          logger.LevelDebug,
		Name:           "logwisp",
		Directory:      "/var/log/logwisp",
		BufferSize:     defaultBufferSize,
		MaxSizeMB:      5,   // 5MB for logwisp logs
		MaxTotalSizeMB: 50,  // 50MB total log size
		MinDiskFreeMB:  100, // 100MB minimum free space
	}

	// Monitor defaults
	c.Monitor = MonitorConfig{
		Paths:       make(map[string]MonitorPath),
		CheckPeriod: minCheckPeriod,
	}

	// Stream defaults
	c.Stream = StreamConfig{
		BufferSize:      defaultBufferSize,
		FlushIntervalMs: 1000,
		RateLimit: RateLimitConfig{
			RequestsPerSecond:    100,
			BurstSize:            1000,
			ClientTimeoutMinutes: 5,
		},
	}
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	// Validate operation mode
	if err := c.validateMode(); err != nil {
		return err
	}

	// Validate port
	if err := c.validatePort(); err != nil {
		return err
	}

	// Validate logger settings
	if err := c.validateLogger(); err != nil {
		return err
	}

	// Validate security settings
	if err := c.validateSecurity(); err != nil {
		return err
	}

	// Validate monitor configuration in service mode
	if c.Mode == ServiceMode {
		if err := c.validateMonitor(); err != nil {
			return err
		}
	}

	// Validate stream configuration
	return c.validateStream()
}

func (c *Config) validateMode() error {
	if c.Mode != ServiceMode && c.Mode != ViewerMode {
		return &ValidationError{
			Field:   "mode",
			Message: fmt.Sprintf("invalid operation mode: %s", c.Mode),
		}
	}
	return nil
}

func (c *Config) validatePort() error {
	if c.Port < minPort || c.Port > maxPort {
		return &ValidationError{
			Field:   "port",
			Message: fmt.Sprintf("port must be between %d and %d", minPort, maxPort),
		}
	}
	return nil
}

func (c *Config) validateLogger() error {
	validLevels := map[int64]bool{
		logger.LevelDebug: true,
		logger.LevelInfo:  true,
		logger.LevelWarn:  true,
		logger.LevelError: true,
	}

	if !validLevels[c.Logger.Level] {
		return &ValidationError{
			Field:   "logger.level",
			Message: fmt.Sprintf("invalid log level: %d", c.Logger.Level),
		}
	}

	if c.Logger.BufferSize < minBufferSize {
		return &ValidationError{
			Field:   "logger.buffer_size",
			Message: fmt.Sprintf("buffer size must be at least %d", minBufferSize),
		}
	}

	if c.Logger.MaxSizeMB <= 0 {
		return &ValidationError{
			Field:   "logger.max_size_mb",
			Message: "max size must be positive",
		}
	}

	if c.Logger.MaxTotalSizeMB <= 0 {
		return &ValidationError{
			Field:   "logger.max_total_size_mb",
			Message: "total maximum size must be positive",
		}
	}

	if c.Logger.MinDiskFreeMB <= 0 {
		return &ValidationError{
			Field:   "logger.min_disk_free_mb",
			Message: "minimum free disk space must be positive",
		}
	}

	if c.Logger.MaxTotalSizeMB <= c.Logger.MaxSizeMB {
		return &ValidationError{
			Field: "logger.max_total_size_mb",
			Message: fmt.Sprintf("total maximum size (%d MB) must be greater than individual file size limit (%d MB)",
				c.Logger.MaxTotalSizeMB, c.Logger.MaxSizeMB),
		}
	}

	return nil
}

func (c *Config) validateSecurity() error {
	if c.Security.TLSEnabled {
		if c.Security.TLSCertFile == "" || c.Security.TLSKeyFile == "" {
			return &ValidationError{
				Field:   "security.tls",
				Message: "TLS enabled but certificate or key file not specified",
			}
		}

		// Check certificate files
		if _, err := os.Stat(c.Security.TLSCertFile); err != nil {
			return &ValidationError{
				Field:   "security.tls_cert_file",
				Message: fmt.Sprintf("certificate file not found: %s", c.Security.TLSCertFile),
			}
		}
		if _, err := os.Stat(c.Security.TLSKeyFile); err != nil {
			return &ValidationError{
				Field:   "security.tls_key_file",
				Message: fmt.Sprintf("key file not found: %s", c.Security.TLSKeyFile),
			}
		}
	}

	if c.Security.AuthEnabled {
		if c.Security.AuthUsername == "" || c.Security.AuthPassword == "" {
			return &ValidationError{
				Field:   "security.auth",
				Message: "auth enabled but username or password not specified",
			}
		}
	}

	return nil
}

func (c *Config) validateMonitor() error {
	if len(c.Monitor.Paths) == 0 {
		return &ValidationError{
			Field:   "monitor.paths",
			Message: "at least one monitored path must be specified in service mode",
		}
	}

	for key, target := range c.Monitor.Paths {
		if target.Path == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("monitor.paths.%s.path", key),
				Message: "path cannot be empty",
			}
		}

		if !target.IsFile {
			updatedTarget := target
			if target.Pattern == "" {
				updatedTarget.Pattern = defaultPattern
				c.Monitor.Paths[key] = updatedTarget // Update the whole struct
			}

			if _, err := os.Stat(target.Path); err != nil {
				return &ValidationError{
					Field:   fmt.Sprintf("monitor.paths.%s.path", key),
					Message: fmt.Sprintf("directory not found: %s", target.Path),
				}
			}
		}
	}

	return nil
}

func (c *Config) validateStream() error {
	if c.Stream.RateLimit.RequestsPerSecond < 0 {
		return &ValidationError{
			Field:   "stream.rate_limit.requests_per_second",
			Message: "requests per second cannot be negative",
		}
	}

	if c.Stream.RateLimit.BurstSize < 0 {
		return &ValidationError{
			Field:   "stream.rate_limit.burst_size",
			Message: "burst size cannot be negative",
		}
	}

	if c.Stream.RateLimit.ClientTimeoutMinutes < 0 {
		return &ValidationError{
			Field:   "stream.rate_limit.client_timeout_minutes",
			Message: "client timeout cannot be negative",
		}
	}

	if c.Stream.FlushIntervalMs < 100 {
		return &ValidationError{
			Field:   "stream.flush_interval_ms",
			Message: "flush interval must be at least 100ms",
		}
	}

	return nil
}

// MonitorTarget represents a validated monitoring target
type MonitorTarget struct {
	Path    string
	Pattern string
	IsFile  bool
}