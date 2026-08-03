package core

import (
	"fmt"
	"os"
	"path/filepath"
)

func AcquireLock(env Environment) (func(), error) {
	if err := EnsureRuntimeDirs(env); err != nil {
		return nil, err
	}
	path := filepath.Join(env.DataDir, "operation.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("operation lock exists: %s", path)
	}
	_, _ = fmt.Fprintf(file, "pid=%d\n", os.Getpid())
	_ = file.Close()
	return func() { _ = os.Remove(path) }, nil
}
