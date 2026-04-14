package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

var rootLogger *slog.Logger

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
)

type dualHandler struct {
	handlers []slog.Handler
}

func (d *dualHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range d.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (d *dualHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range d.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *dualHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(d.handlers))
	for i, h := range d.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &dualHandler{handlers: hs}
}

func (d *dualHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(d.handlers))
	for i, h := range d.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &dualHandler{handlers: hs}
}

type colorHandler struct {
	w     io.Writer
	level slog.Level
}

func (h *colorHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *colorHandler) Handle(_ context.Context, record slog.Record) error {
	color, levelStr := colorWhite, record.Level.String()
	switch record.Level {
	case slog.LevelDebug:
		color, levelStr = colorWhite, "DEBUG"
	case slog.LevelInfo:
		color, levelStr = colorBlue, "INFO"
	case slog.LevelWarn:
		color, levelStr = colorYellow, "WARNING"
	case slog.LevelError:
		color, levelStr = colorRed, "ERROR"
	}
	timeStr := record.Time.Format("15:04:05")
	var modulePrefix, argsStr string
	hasOtherAttrs := false
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == "module" {
			modulePrefix = fmt.Sprintf("%v", a.Value)
		} else {
			if !hasOtherAttrs {
				argsStr = " ("
				hasOtherAttrs = true
			} else {
				argsStr += ", "
			}
			argsStr += fmt.Sprintf("%s=%v", a.Key, a.Value)
		}
		return true
	})
	if hasOtherAttrs {
		argsStr += ")"
	}
	var prefix string
	if modulePrefix != "" {
		prefix = fmt.Sprintf("%s[%s]%s ", colorGray, modulePrefix, colorReset)
	}
	_, err := fmt.Fprintf(h.w, "%s%s%s%s: %s%s [%s]\n",
		prefix, color, levelStr, colorReset, record.Message, argsStr, timeStr)
	return err
}

func (h *colorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h // stateless
}
func (h *colorHandler) WithGroup(name string) slog.Handler {
	return h // stateless
}

type fileHandler struct {
	w     io.Writer
	level slog.Level
}

func (h *fileHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *fileHandler) Handle(_ context.Context, record slog.Record) error {
	levelStr := record.Level.String()
	switch record.Level {
	case slog.LevelDebug:
		levelStr = "DEBUG"
	case slog.LevelInfo:
		levelStr = "INFO"
	case slog.LevelWarn:
		levelStr = "WARNING"
	case slog.LevelError:
		levelStr = "ERROR"
	}
	timeStr := record.Time.Format("15:04:05")
	var modulePrefix, argsStr string
	hasOtherAttrs := false
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == "module" {
			modulePrefix = fmt.Sprintf("%v", a.Value)
		} else {
			if !hasOtherAttrs {
				argsStr = " ("
				hasOtherAttrs = true
			} else {
				argsStr += ", "
			}
			argsStr += fmt.Sprintf("%s=%v", a.Key, a.Value)
		}
		return true
	})
	if hasOtherAttrs {
		argsStr += ")"
	}
	var prefix string
	if modulePrefix != "" {
		prefix = fmt.Sprintf("[%s] ", modulePrefix)
	}
	_, err := fmt.Fprintf(h.w, "%s%s: %s%s [%s]\n",
		prefix, levelStr, record.Message, argsStr, timeStr)
	return err
}

func (h *fileHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h // stateless
}
func (h *fileHandler) WithGroup(name string) slog.Handler {
	return h // stateless
}

func init() {
	logPath := filepath.Join(os.TempDir(), "fibrum-pdf.log")
	fmt.Printf("writing all logs to: %s\n", logPath)
	var handlers []slog.Handler
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[logger warning]%s Could not open app.log for writing: %v. Logging to stdout only.\n", colorYellow, colorReset, err)
	} else {
		handlers = append(handlers, &fileHandler{w: file, level: slog.LevelDebug})
	}
	stdoutLevel := slog.LevelInfo
	handlers = append(handlers, &colorHandler{w: os.Stdout, level: stdoutLevel})
	rootLogger = slog.New(&dualHandler{handlers: handlers})
}

func GetLogger(prefix string) *slog.Logger {
	return rootLogger.With("module", prefix)
}
