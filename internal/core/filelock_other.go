//go:build !linux

package core

import (
	"os"
	"sync"
)

var fallbackLockFiles sync.Map

func tryAdvisoryLock(file *os.File) (bool, error) {
	guardPath := file.Name() + ".guard"
	guard, err := os.OpenFile(guardPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := guard.Close(); err != nil {
		_ = os.Remove(guardPath)
		return false, err
	}
	fallbackLockFiles.Store(file, guardPath)
	return true, nil
}

func releaseAdvisoryLock(file *os.File) error {
	value, ok := fallbackLockFiles.LoadAndDelete(file)
	if !ok {
		return nil
	}
	return os.Remove(value.(string))
}
