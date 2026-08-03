package core

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func NewRequestID() string {
	return "req-" + NewShortID()
}

func NewShortID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().Format("20060102150405")
	}
	return hex.EncodeToString(b[:])
}
