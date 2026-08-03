package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

const (
	colorReset  = "\033[0m"
	colorGray   = "\033[90m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
)

type devHandler struct {
	mu     *sync.Mutex
	out    io.Writer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
}

func NewDevHandler(out io.Writer, level slog.Leveler) slog.Handler {
	if level == nil {
		level = slog.LevelInfo
	}
	return &devHandler{
		mu:    &sync.Mutex{},
		out:   out,
		level: level,
	}
}

func (h *devHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}
func (h *devHandler) Handle(_ context.Context, r slog.Record) error {
	levelStr, color := levelDisplay(r.Level)

	timeStr := r.Time.Format("15:04:05")

	var b []byte
	b = append(b, fmt.Sprintf("%s[%s]%s ", colorGray, timeStr, colorReset)...)
	b = append(b, fmt.Sprintf("%s[%-5s]%s ", color, levelStr, colorReset)...)
	b = append(b, r.Message...)

	var errStr string
	attrs := make([]string, 0, r.NumAttrs()+len(h.attrs))

	appendAttr := func(a slog.Attr) bool {
		if a.Key == "" {
			return true
		}
		// Detect an error value structurally, not by key name.
		if err, ok := a.Value.Any().(error); ok {
			errStr = err.Error()
			return true
		}
		attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value.Any()))
		return true
	}

	for _, a := range h.attrs {
		appendAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		return appendAttr(a)
	})

	for _, a := range attrs {
		b = append(b, ' ')
		b = append(b, a...)
	}
	if errStr != "" {
		b = append(b, ' ')
		b = append(b, colorRed...)
		b = append(b, errStr...)
		b = append(b, colorReset...)
	}
	b = append(b, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write(b)
	return err
}

func (h *devHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, attrs...)
	return &devHandler{
		mu:     h.mu,
		out:    h.out,
		level:  h.level,
		attrs:  newAttrs,
		groups: h.groups,
	}
}

func (h *devHandler) WithGroup(name string) slog.Handler {
	return h
}

func levelDisplay(level slog.Level) (string, string) {
	switch {
	case level < slog.LevelInfo:
		return "DEBUG", colorGray
	case level < slog.LevelWarn:
		return "INFO", colorGreen
	case level < slog.LevelError:
		return "WARN", colorYellow
	default:
		return "ERROR", colorRed
	}
}
