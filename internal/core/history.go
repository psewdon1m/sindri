package core

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const maxHistoryEntries = 100

func AppendHistory(env Environment, entry HistoryEntry) error {
	if err := EnsureRuntimeDirs(env); err != nil {
		return err
	}
	unlock, err := acquireFileLock(filepath.Join(env.DataDir, "history.lock"), 5*time.Second, 30*time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(env.DataDir, "history.jsonl")
	entries, _ := ReadHistory(env, maxHistoryEntries-1)
	entries = append([]HistoryEntry{entry}, entries...)
	if len(entries) > maxHistoryEntries {
		entries = entries[:maxHistoryEntries]
	}
	file, err := os.CreateTemp(env.DataDir, ".history-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0640); err != nil {
		_ = file.Close()
		return err
	}
	enc := json.NewEncoder(file)
	for _, item := range entries {
		if err := enc.Encode(item); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func ReadHistory(env Environment, limit int) ([]HistoryEntry, error) {
	path := filepath.Join(env.DataDir, "history.jsonl")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var entries []HistoryEntry
	for scanner.Scan() {
		var entry HistoryEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
		if limit > 0 && len(entries) >= limit {
			break
		}
	}
	return entries, scanner.Err()
}
