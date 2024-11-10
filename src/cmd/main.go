// File: logwisp/src/cmd/logwisp/main.go

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
	"logwisp/src/internal/viewer"
	"logwisp/src/pkg/logger"
)

var (
	configFile string
	viewMode   bool
)

func init() {
	flag.StringVar(&configFile, "config", "/etc/logwisp/logwisp.toml", "path to configuration file")
	flag.BoolVar(&viewMode, "view", false, "run in viewer mode")
	flag.Parse()
}

func main() {
	// Create base context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override mode if -view flag is set
	if viewMode {
		cfg.Mode = config.ViewerMode
	}

	// Initialize logger
	logCfg := &logger.Config{
		Level:      cfg.Logger.Level,
		Directory:  cfg.Logger.Directory,
		BufferSize: cfg.Logger.BufferSize,
	}

	if err := logger.Init(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	// Ensure logger shutdown
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := logger.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down logger: %v\n", err)
		}
	}()

	// Log startup information
	logger.Info(ctx, "Starting logwisp",
		"mode", cfg.Mode,
		"version", "0.1.0",
		"config", configFile)

	// Create done channel for graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	// Initialize appropriate mode
	var app interface {
		Start(context.Context) error
		Stop(context.Context) error
	}

	// Create and configure the appropriate mode
	switch cfg.Mode {
	case config.ServiceMode:
		app, err = service.New(cfg)
		if err != nil {
			logger.Error(ctx, "Failed to initialize service mode", "error", err)
			os.Exit(1)
		}

	case config.ViewerMode:
		app, err = viewer.New(cfg)
		if err != nil {
			logger.Error(ctx, "Failed to initialize viewer mode", "error", err)
			os.Exit(1)
		}

	default:
		logger.Error(ctx, "Invalid operation mode", "mode", cfg.Mode)
		os.Exit(1)
	}

	// Start the application
	if err := app.Start(ctx); err != nil {
		logger.Error(ctx, "Failed to start application", "error", err)
		os.Exit(1)
	}

	// Wait for shutdown signal
	select {
	case sig := <-done:
		logger.Info(ctx, "Received shutdown signal", "signal", sig)
	case <-ctx.Done():
		logger.Info(ctx, "Context cancelled")
	}

	// Initiate graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second) // Fixed 5 second timeout
	defer shutdownCancel()

	if err := app.Stop(shutdownCtx); err != nil {
		logger.Error(ctx, "Error during shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info(ctx, "Shutdown complete")
}
