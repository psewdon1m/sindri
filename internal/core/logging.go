package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RunLog struct {
	Reference string
	file      *os.File
}

func NewRunLog(env Environment, requestID string, action string) *RunLog {
	reference := fmt.Sprintf("run-%s-%s", time.Now().Format("20060102-150405"), NewShortID())
	path := filepath.Join(env.LogDir, "runs", reference+".log")
	_ = os.MkdirAll(filepath.Dir(path), 0750)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return &RunLog{Reference: reference}
	}
	log := &RunLog{Reference: reference, file: file}
	log.Write("request_id=%s action=%s", requestID, action)
	return log
}

func (l *RunLog) Write(format string, args ...interface{}) {
	if l == nil || l.file == nil {
		return
	}
	line := fmt.Sprintf(format, args...)
	line = RedactSecrets(line)
	_, _ = fmt.Fprintf(l.file, "%s %s\n", time.Now().Format(time.RFC3339), line)
}

func (l *RunLog) Close() {
	if l != nil && l.file != nil {
		_ = l.file.Close()
	}
}

func RedactSecrets(input string) string {
	secretWords := []string{"password", "token", "secret", "private_key", "privkey"}
	out := input
	for _, word := range secretWords {
		lower := strings.ToLower(out)
		idx := strings.Index(lower, word+"=")
		for idx >= 0 {
			start := idx + len(word) + 1
			end := strings.IndexAny(out[start:], " \t\r\n")
			if end < 0 {
				out = out[:start] + "[REDACTED]"
				break
			}
			end += start
			out = out[:start] + "[REDACTED]" + out[end:]
			lower = strings.ToLower(out)
			idx = strings.Index(lower, word+"=")
		}
	}
	return out
}
