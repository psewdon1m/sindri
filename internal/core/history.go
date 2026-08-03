package core

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

const maxHistoryEntries = 100

func AppendHistory(env Environment, entry HistoryEntry) error {
	if err := EnsureRuntimeDirs(env); err != nil {
		return err
	}
	path := filepath.Join(env.DataDir, "history.jsonl")
	entries, _ := ReadHistory(env, maxHistoryEntries-1)
	entries = append([]HistoryEntry{entry}, entries...)
	if len(entries) > maxHistoryEntries {
		entries = entries[:maxHistoryEntries]
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	for _, item := range entries {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
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
