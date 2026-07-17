package logger

import (
	"log/slog"
	"os"
	"strings"
)

var rootLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: configuredLevel(),
}))

func configuredLevel() slog.Level {
	switch strings.ToLower(os.Getenv("FIBRUMPDF_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

func GetLogger(module string) *slog.Logger {
	return rootLogger.With("module", module)
}
