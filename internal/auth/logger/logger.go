package logger

import (
	"log/slog"
	"os"
	"strings"
)

func New(env string, levelStr string) *slog.Logger {
	level := parseLevel(levelStr)

	var handler slog.Handler
	if isProd(env) {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     level,
			AddSource: true,
		})
	} else {
		handler = NewDevHandler(os.Stdout, level)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

func isProd(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "production", "prod":
		return true
	default:
		return false
	}
}

func parseLevel(levelStr string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
