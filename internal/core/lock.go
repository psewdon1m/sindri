package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func AcquireLock(env Environment) (func(), error) {
	if err := EnsureRuntimeDirs(env); err != nil {
		return nil, err
	}
	return acquireFileLock(filepath.Join(env.DataDir, "operation.lock"), 0, 0)
}

type lockRecord struct {
	ID           string    `json:"id"`
	PID          int       `json:"pid"`
	BootID       string    `json:"boot_id,omitempty"`
	ProcessStart string    `json:"process_start,omitempty"`
	Kind         string    `json:"kind,omitempty"`
	Status       string    `json:"status,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ReleasedAt   time.Time `json:"released_at,omitempty"`
}

// acquireFileLock uses a Linux advisory lock as the source of truth. The
// kernel releases it when a process exits for any reason, including SIGKILL,
// so a diagnostic file left on disk can never block a later operation by
// itself. PID, boot ID and process start time remain in the file for operator
// diagnostics and compatibility with lock files written by older versions.
func acquireFileLock(path string, wait, _ time.Duration) (func(), error) {
	deadline := time.Now().Add(wait)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0640)
		if err != nil {
			return nil, err
		}
		locked, lockErr := tryAdvisoryLock(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, lockErr
		}
		if !locked {
			_ = file.Close()
			if wait <= 0 || time.Now().After(deadline) {
				return nil, lockBusyError(path)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		previous := readLockBody(file)
		// A pre-flock Sindri process can still be alive while holding an old
		// PID-only lock. Respect it during rolling upgrades. Records created by
		// this implementation are governed by the kernel lock we already own.
		if legacyLockOwnerActive(previous) {
			_ = releaseAdvisoryLock(file)
			_ = file.Close()
			if wait <= 0 || time.Now().After(deadline) {
				return nil, lockBusyError(path)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		record := lockRecord{
			ID:           NewShortID(),
			PID:          os.Getpid(),
			BootID:       currentBootID(),
			ProcessStart: processStartTime(os.Getpid()),
			Kind:         "flock",
			Status:       "active",
			CreatedAt:    time.Now().UTC(),
		}
		if err := writeLockRecord(file, record); err != nil {
			_ = releaseAdvisoryLock(file)
			_ = file.Close()
			return nil, err
		}

		var once sync.Once
		return func() {
			once.Do(func() {
				record.Status = "released"
				record.ReleasedAt = time.Now().UTC()
				_ = writeLockRecord(file, record)
				_ = releaseAdvisoryLock(file)
				_ = file.Close()
			})
		}, nil
	}
}

func readLockBody(file *os.File) []byte {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(file, 16*1024))
	return body
}

func writeLockRecord(file *os.File, record lockRecord) error {
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(record); err != nil {
		return err
	}
	return file.Sync()
}

func legacyLockOwnerActive(body []byte) bool {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return false
	}
	var record lockRecord
	if json.Unmarshal(body, &record) == nil {
		if record.Kind == "flock" || record.Status == "released" {
			return false
		}
		return processMatches(record)
	}
	if strings.HasPrefix(text, "pid=") {
		pid, _ := strconv.Atoi(strings.TrimPrefix(text, "pid="))
		return processMatches(lockRecord{PID: pid})
	}
	// A malformed file cannot represent a verifiable live owner. Since the
	// advisory lock is already ours, treating it as stale is safe.
	return false
}

func processMatches(record lockRecord) bool {
	if record.PID <= 0 || runtime.GOOS != "linux" {
		return false
	}
	if record.BootID != "" && record.BootID != currentBootID() {
		return false
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(record.PID))); err != nil {
		return false
	}
	if record.ProcessStart != "" && record.ProcessStart != processStartTime(record.PID) {
		return false
	}
	return true
}

func processStartTime(pid int) string {
	if runtime.GOOS != "linux" || pid <= 0 {
		return ""
	}
	body, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	// The command name in /proc/PID/stat may contain spaces and parentheses.
	// Fields after the final ") " start at field 3; process start time is 22.
	closing := strings.LastIndex(string(body), ") ")
	if closing < 0 {
		return ""
	}
	fields := strings.Fields(string(body)[closing+2:])
	if len(fields) <= 19 {
		return ""
	}
	return fields[19]
}

func lockBusyError(path string) error {
	body, _ := os.ReadFile(path)
	var record lockRecord
	if json.Unmarshal(body, &record) == nil && record.PID > 0 {
		return fmt.Errorf("operation lock is held by PID %d: %s", record.PID, path)
	}
	return fmt.Errorf("operation lock exists: %s", path)
}

func currentBootID() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	body, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(body))
}
