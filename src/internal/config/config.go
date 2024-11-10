// File: logwisp/src/internal/config/config.go

package config

import (
	"fmt"
	"logwisp/src/pkg/tinytoml"
	"os"
	"path/filepath"
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
	maxNestingLevel   = 3
	defaultPattern    = "*.log"
)

// Config holds the complete configuration for logwisp
type Config struct {
	// Mode determines whether to run as service or viewer
	Mode OperationMode `toml:"mode"`
	// Port defines the service listening port
	Port int `toml:"port"`

	// Logger configuration section
	Logger struct {
		Level      string `toml:"level" validate:"oneof=DEBUG INFO WARN ERROR"`
		Directory  string `toml:"directory"`
		BufferSize int    `toml:"buffer_size"`
	} `toml:"logger"`

	// Security configuration section
	Security struct {
		TLSEnabled  bool   `toml:"tls_enabled"`
		TLSCertFile string `toml:"tls_cert_file"`
		TLSKeyFile  string `toml:"tls_key_file"`

		AuthEnabled  bool   `toml:"auth_enabled"`
		AuthUsername string `toml:"auth_username"`
		AuthPassword string `toml:"auth_password"`
	} `toml:"security"`

	// Monitor configuration
	Monitor struct {
		// Targets is a collection of monitored paths
		Paths       map[string]MonitorPath `toml:"paths"`
		CheckPeriod int                    `toml:"check_period_ms"`
	} `toml:"monitor"`

	// Stream configuration
	Stream struct {
		BufferSize      int             `toml:"buffer_size"`
		FlushIntervalMs int             `toml:"flush_interval_ms"`
		RateLimit       RateLimitConfig `toml:"rate_limit"`
	} `toml:"stream"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	RequestsPerSecond    int `toml:"requests_per_second"`
	BurstSize            int `toml:"burst_size"`
	ClientTimeoutMinutes int `toml:"client_timeout_minutes"`
}

// MonitorPath represents a path to be monitored
type MonitorPath struct {
	Path    string `toml:"path"`
	Pattern string `toml:"pattern"`
	IsFile  bool   `toml:"is_file"`
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// LoadConfig reads and parses the configuration file
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	if err := tinytoml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	cfg.setDefaults()
	return cfg, nil
}

// setDefaults sets default values for optional fields
func (c *Config) setDefaults() {
	if c.Logger.Level == "" {
		c.Logger.Level = "INFO"
	}
	if c.Logger.Directory == "" {
		c.Logger.Directory = filepath.Join(os.TempDir(), "logwisp", "logs")
	}
	if c.Logger.BufferSize < minBufferSize {
		c.Logger.BufferSize = defaultBufferSize
	}
	if c.Monitor.CheckPeriod < minCheckPeriod {
		c.Monitor.CheckPeriod = minCheckPeriod
	}
	if c.Stream.BufferSize < minBufferSize {
		c.Stream.BufferSize = defaultBufferSize
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
	switch c.Logger.Level {
	case "", "DEBUG", "INFO", "WARN", "ERROR":
		// Valid levels
	default:
		return &ValidationError{
			Field:   "logger.level",
			Message: fmt.Sprintf("invalid log level: %s", c.Logger.Level),
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

	return nil
}

// GetMonitorTargets returns the list of monitoring targets
func (c *Config) GetMonitorTargets() []MonitorTarget {
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

// MonitorTarget represents a validated monitoring target
type MonitorTarget struct {
	Path    string
	Pattern string
	IsFile  bool
}
