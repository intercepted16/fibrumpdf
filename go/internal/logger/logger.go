package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"path/filepath"
)

var rootLogger *slog.Logger

var tempDir = os.TempDir()

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
)

func init() {
	var fileHandler *customHandler

	logPath := filepath.Join(tempDir, "fibrum-pdf.log")
	
	fmt.Printf("writing all logs to: %s\n", logPath)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {

		fmt.Fprintf(os.Stderr, "%s[logger warning]%s Could not open app.log for writing: %v. Logging to stdout only.\n", colorYellow, colorReset, err)
	} else {
		fileHandler = &customHandler{
			w:          file,
			level:      slog.LevelDebug,
			withColors: false,
		}

	}

	var stdoutLevel slog.Level
	debugEnv := os.Getenv("TOMD_DEBUG")
	debugEnabled, _ := strconv.ParseBool(debugEnv)
	if debugEnabled {
		stdoutLevel = slog.LevelDebug
	} else {
		stdoutLevel = slog.LevelInfo
	}

	colorHandler := &customHandler{
		w:          os.Stdout,
		level:      stdoutLevel,
		withColors: true,
	}

	var mh multiHandler
	if fileHandler != nil {
		mh = multiHandler{
			file:   fileHandler,
			stdout: colorHandler,
		}
	} else {

		mh = multiHandler{
			file:   nil,
			stdout: colorHandler,
		}
	}

	rootLogger = slog.New(&mh)
}

func GetLogger(prefix string) *slog.Logger {
	return rootLogger.With("module", prefix)
}

type customHandler struct {
	w          io.Writer
	level      slog.Level
	attrs      []slog.Attr
	group      string
	prefix     string
	withColors bool
}

func (h *customHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *customHandler) Handle(_ context.Context, record slog.Record) error {
	var color string
	var levelStr string

	switch record.Level {
	case slog.LevelDebug:
		color = colorWhite
		levelStr = "DEBUG"
	case slog.LevelInfo:
		color = colorBlue
		levelStr = "INFO"
	case slog.LevelWarn:
		color = colorYellow
		levelStr = "WARNING"
	case slog.LevelError:
		color = colorRed
		levelStr = "ERROR"
	default:
		color = colorWhite
		levelStr = record.Level.String()
	}

	timeStr := record.Time.Format("15:04:05")

	var modulePrefix string
	var argsStr string
	hasOtherAttrs := false

	for _, a := range h.attrs {
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
	}

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
		if h.withColors {
			prefix = fmt.Sprintf("%s[%s]%s ", colorGray, modulePrefix, colorReset)
		} else {
			prefix = fmt.Sprintf("[%s] ", modulePrefix)
		}
	}

	if h.withColors {
		_, err := fmt.Fprintf(h.w, "%s%s%s%s: %s%s [%s]\n",
			prefix,
			color, levelStr, colorReset,
			record.Message,
			argsStr,
			timeStr)
		return err
	} else {
		_, err := fmt.Fprintf(h.w, "%s%s: %s%s [%s]\n",
			prefix,
			levelStr,
			record.Message,
			argsStr,
			timeStr)
		return err
	}
}

func (h *customHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &customHandler{
		w:          h.w,
		level:      h.level,
		attrs:      newAttrs,
		group:      h.group,
		prefix:     h.prefix,
		withColors: h.withColors,
	}
}

func (h *customHandler) WithGroup(name string) slog.Handler {
	return &customHandler{
		w:          h.w,
		level:      h.level,
		attrs:      h.attrs,
		group:      name,
		prefix:     h.prefix,
		withColors: h.withColors,
	}
}

type multiHandler struct {
	file   slog.Handler
	stdout slog.Handler
}

func (mh *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return mh.file.Enabled(ctx, level) || mh.stdout.Enabled(ctx, level)
}

func (mh *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	if mh.file.Enabled(ctx, record.Level) {
		if err := mh.file.Handle(ctx, record); err != nil {
			return err
		}
	}

	if mh.stdout.Enabled(ctx, record.Level) {
		if err := mh.stdout.Handle(ctx, record); err != nil {
			return err
		}
	}

	return nil
}

func (mh *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{
		file:   mh.file.WithAttrs(attrs),
		stdout: mh.stdout.WithAttrs(attrs),
	}
}

func (mh *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{
		file:   mh.file.WithGroup(name),
		stdout: mh.stdout.WithGroup(name),
	}
}
