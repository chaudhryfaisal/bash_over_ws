package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
}

// New creates a new logger with the specified level
func New(level string) *Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &Logger{Logger: logger}
}

// WithSessionID adds a session ID to the logger context
func (l *Logger) WithSessionID(sessionID string) *Logger {
	return &Logger{Logger: l.Logger.With("session_id", sessionID)}
}

// WithClientAddr adds a client address to the logger context
func (l *Logger) WithClientAddr(addr string) *Logger {
	return &Logger{Logger: l.Logger.With("client_addr", addr)}
}

// WithComponent adds a component name to the logger context
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{Logger: l.Logger.With("component", component)}
}