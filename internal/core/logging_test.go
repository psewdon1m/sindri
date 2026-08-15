package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunLogRedactsSecretsAndEnforcesSizeLimit(t *testing.T) {
	env := testCoreEnvironment(t)
	log := NewRunLog(env, "request", "test.action")
	log.Write("password=hunter2 token: abc123 Authorization: Bearer credential")
	longLine := strings.Repeat("x", maxRunLogLineLength*2)
	for index := 0; index < 400; index++ {
		log.Write("%s", longLine)
	}
	log.Close()

	path := filepath.Join(env.LogDir, "runs", log.Reference+".log")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, secret := range []string{"hunter2", "abc123", "credential"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q was written to the run log", secret)
		}
	}
	if int64(len(body)) > maxRunLogBytes {
		t.Fatalf("run log grew to %d bytes; limit is %d", len(body), maxRunLogBytes)
	}
}
