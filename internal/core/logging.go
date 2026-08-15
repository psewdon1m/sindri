package core

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type RunLog struct {
	Reference string
	file      *os.File
	written   int64
}

const (
	maxRunLogBytes      = int64(5 * 1024 * 1024)
	maxRunLogDirectory  = int64(64 * 1024 * 1024)
	maxRunLogAge        = 30 * 24 * time.Hour
	maxRunLogLineLength = 16 * 1024
)

var (
	secretAssignment = regexp.MustCompile(`(?i)(password|token|secret|private_key|privkey)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}]+)`)
	bearerCredential = regexp.MustCompile(`(?i)bearer\s+[^\s,}]+`)
)

func NewRunLog(env Environment, requestID string, action string) *RunLog {
	reference := fmt.Sprintf("run-%s-%s", time.Now().Format("20060102-150405"), NewShortID())
	directory := filepath.Join(env.LogDir, "runs")
	_ = os.MkdirAll(directory, 0750)
	pruneRunLogs(directory)
	path := filepath.Join(directory, reference+".log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return &RunLog{Reference: reference}
	}
	log := &RunLog{Reference: reference, file: file}
	log.Write("request_id=%s action=%s", requestID, action)
	return log
}

func (l *RunLog) Write(format string, args ...interface{}) {
	if l == nil || l.file == nil || l.written >= maxRunLogBytes {
		return
	}
	line := fmt.Sprintf(format, args...)
	line = RedactSecrets(line)
	if len(line) > maxRunLogLineLength {
		line = line[:maxRunLogLineLength] + " [TRUNCATED]"
	}
	entry := fmt.Sprintf("%s %s\n", time.Now().Format(time.RFC3339), line)
	remaining := maxRunLogBytes - l.written
	if int64(len(entry)) > remaining {
		entry = entry[:remaining]
	}
	written, _ := l.file.WriteString(entry)
	l.written += int64(written)
}

func (l *RunLog) Close() {
	if l != nil && l.file != nil {
		_ = l.file.Close()
	}
}

func RedactSecrets(input string) string {
	out := secretAssignment.ReplaceAllString(input, "$1$2[REDACTED]")
	out = bearerCredential.ReplaceAllString(out, "Bearer [REDACTED]")
	return out
}

func pruneRunLogs(directory string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	type retainedFile struct {
		path    string
		modTime time.Time
		size    int64
	}
	now := time.Now()
	files := make([]retainedFile, 0, len(entries))
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".log") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if now.Sub(info.ModTime()) > maxRunLogAge {
			_ = os.Remove(path)
			continue
		}
		files = append(files, retainedFile{path: path, modTime: info.ModTime(), size: info.Size()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })
	for _, file := range files {
		if total <= maxRunLogDirectory {
			break
		}
		if os.Remove(file.path) == nil {
			total -= file.size
		}
	}
}
