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

	"github.com/LixenWraith/logger"
)

var (
	configFile string
	viewMode   bool
)

func init() {
	// TODO: cli > env > default
	flag.StringVar(&configFile, "config", "/usr/local/etc/logwisp/logwisp.toml", "path to configuration file")
	flag.BoolVar(&viewMode, "view", false, "run in viewer mode")
	flag.Parse()
}

func main() {
	// Create base context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load initial configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override mode if -view flag is set
	if viewMode {
		cfg.Mode = config.ViewerMode
	}

	// Initialize logger
	if err := logger.Init(ctx, &cfg.Logger); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	// Ensure logger shutdown
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second) // TODO: check if context cancellation can be used instead
		defer shutdownCancel()
		if err := logger.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down logger: %v\n", err)
		}
	}()

	// Log startup information
	logger.Info(ctx, "Starting logwisp",
		"mode", cfg.Mode,
		"config", configFile)

	// Create signal channels
	shutdown := make(chan os.Signal, 1) // Shutdown, service stop
	reload := make(chan os.Signal, 1)   // Reload config

	// Register signal handlers and ensure cleanup
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(shutdown)
	defer signal.Stop(reload)

	// Create context for reload handler
	reloadCtx, reloadCancel := context.WithCancel(ctx)
	defer reloadCancel()

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

	// Handle configuration reloads
	go func() {
		for {
			select {
			case <-reloadCtx.Done():
				logger.Info(ctx, "Stopping config reload handler")
				return
			case <-reload:
				logger.Info(ctx, "Received reload signal, reloading configuration")
				if err := cfg.Reload(configFile); err != nil {
					logger.Error(ctx, "Failed to reload configuration", "error", err)
					continue
				}
				logger.Info(ctx, "Configuration reloaded successfully")
			}
		}
	}()

	// Wait for shutdown signal
	select {
	case sig := <-shutdown:
		logger.Info(ctx, "Received shutdown signal", "signal", sig)
	case <-ctx.Done():
		logger.Info(ctx, "Context cancelled")
	}

	// Initiate graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := app.Stop(shutdownCtx); err != nil {
		logger.Error(ctx, "Error during shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info(ctx, "Shutdown complete")
}
