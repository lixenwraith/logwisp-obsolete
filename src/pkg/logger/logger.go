// File: logwisp/src/pkg/logger/logger.go

package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	logChannel    chan LogRecord
	isInitialized bool
	once          sync.Once
	logLevel      slog.Level
	logger        *slog.Logger
	mu            sync.RWMutex
	droppedLogs   atomic.Uint64 // Track dropped logs
)

type LogRecord struct {
	Level   slog.Level
	Message string
	Args    []any
	Time    time.Time
}

type Config struct {
	Level      string
	Directory  string
	BufferSize int
}

func Init(cfg *Config) error {
	var initErr error
	once.Do(func() {
		if err := logLevel.UnmarshalText([]byte(cfg.Level)); err != nil {
			initErr = fmt.Errorf("invalid log level: %w", err)
			return
		}

		if err := os.MkdirAll(cfg.Directory, 0755); err != nil {
			initErr = fmt.Errorf("failed to create log directory: %w", err)
			return
		}

		logFile, err := openLogFile(cfg.Directory)
		if err != nil {
			initErr = fmt.Errorf("failed to open log file: %w", err)
			return
		}

		logger = slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
			Level: logLevel,
		}))

		bufferSize := cfg.BufferSize
		if bufferSize < 1 {
			bufferSize = 1000 // Increased default buffer size
		}
		logChannel = make(chan LogRecord, bufferSize)

		// Start log processor with background context
		processCtx, processCancel := context.WithCancel(context.Background())
		go processLogs(processCtx, processCancel)

		isInitialized = true
	})
	return initErr
}

func openLogFile(logDir string) (*os.File, error) {
	now := time.Now()
	filename := fmt.Sprintf("logwisp_%s.log", now.Format("2006-01-02"))
	return os.OpenFile(
		filepath.Join(logDir, filename),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
}

func processLogs(ctx context.Context, cancel context.CancelFunc) {
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case record, ok := <-logChannel:
			if !ok {
				return
			}
			if record.Level >= logLevel {
				logger.LogAttrs(
					context.Background(),
					record.Level,
					record.Message,
					slog.Time("timestamp", record.Time),
					slog.Any("args", record.Args),
				)
			}
		}
	}
}

func log(ctx context.Context, level slog.Level, msg string, args ...any) {
	mu.RLock()
	initialized := isInitialized
	mu.RUnlock()

	if !initialized || level < logLevel {
		return
	}

	record := LogRecord{
		Level:   level,
		Message: msg,
		Args:    args,
		Time:    time.Now(),
	}

	select {
	case logChannel <- record:
		// Successfully queued
	default:
		// Buffer full, increment dropped count and write to stderr
		droppedLogs.Add(1)
		stderr := fmt.Sprintf("[CRITICAL] Log buffer full (dropped: %d): %s\n",
			droppedLogs.Load(), msg)
		os.Stderr.WriteString(stderr)
	}
}

func Debug(ctx context.Context, msg string, args ...any) {
	log(ctx, slog.LevelDebug, msg, args...)
}

func Info(ctx context.Context, msg string, args ...any) {
	log(ctx, slog.LevelInfo, msg, args...)
}

func Warn(ctx context.Context, msg string, args ...any) {
	log(ctx, slog.LevelWarn, msg, args...)
}

func Error(ctx context.Context, msg string, args ...any) {
	log(ctx, slog.LevelError, msg, args...)
}

func Shutdown(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()

	if !isInitialized {
		return nil
	}

	// Close channel after ensuring all logs are processed
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		close(logChannel)
		isInitialized = false

		if dropped := droppedLogs.Load(); dropped > 0 {
			stderr := fmt.Sprintf("[SHUTDOWN] Total dropped logs: %d\n", dropped)
			os.Stderr.WriteString(stderr)
		}
		return nil
	}
}
