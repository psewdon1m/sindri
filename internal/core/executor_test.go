package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestDangerousApprovalMustBeIssuedAndIsSingleUse(t *testing.T) {
	env := testCoreEnvironment(t)
	registry := NewRegistry()
	registry.Add(Scenario{
		ID: "danger.test", Risk: RiskDangerous,
		Steps: []StepSpec{{ID: "execute", Name: "Execute"}},
		Handler: func(_ Context, _ Request, _ map[string]interface{}) Result {
			return Result{Status: StatusSuccess, Changed: true}
		},
	})

	plan := Execute(context.Background(), registry, env, Request{Action: "danger.test", Source: "test"})
	if plan.Status != StatusApprovalRequired || plan.ApprovalID == "" || plan.PlanHash == "" {
		t.Fatalf("expected persisted approval, got %#v", plan)
	}

	forged := Execute(context.Background(), registry, env, Request{
		Action: "danger.test", Source: "test",
		Approval: &Approval{ApprovalID: "approval-deadbeef", PlanHash: plan.PlanHash},
	})
	if forged.Status != StatusFailed || forged.Error == nil || forged.Error.Code != "APPROVAL_INVALID" {
		t.Fatalf("forged approval was not rejected: %#v", forged)
	}

	approvedRequest := Request{
		Action: "danger.test", Source: "test",
		Approval: &Approval{ApprovalID: plan.ApprovalID, PlanHash: plan.PlanHash},
	}
	approved := Execute(context.Background(), registry, env, approvedRequest)
	if approved.Status != StatusSuccess {
		t.Fatalf("issued approval failed: %#v", approved)
	}
	reused := Execute(context.Background(), registry, env, approvedRequest)
	if reused.Status != StatusFailed || reused.Error == nil || reused.Error.Code != "APPROVAL_INVALID" {
		t.Fatalf("approval reuse was not rejected: %#v", reused)
	}
}

func TestAppendHistoryIsSafeUnderConcurrency(t *testing.T) {
	env := testCoreEnvironment(t)
	const count = 30
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if err := AppendHistory(env, HistoryEntry{ID: fmt.Sprintf("entry-%d", index), Action: "meta.version", Status: StatusSuccess}); err != nil {
				t.Errorf("append history: %v", err)
			}
		}(index)
	}
	wait.Wait()
	entries, err := ReadHistory(env, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != count {
		t.Fatalf("expected %d entries, got %d", count, len(entries))
	}
}

func TestAcquireLockReclaimsADeadOwnerAndProtectsAnActiveOwner(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PID and boot ID validation is Linux-specific")
	}
	env := testCoreEnvironment(t)
	if err := EnsureRuntimeDirs(env); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.DataDir, "operation.lock")
	stale, _ := json.Marshal(lockRecord{ID: "stale", PID: 999999, BootID: currentBootID(), CreatedAt: time.Now().UTC()})
	if err := os.WriteFile(path, stale, 0640); err != nil {
		t.Fatal(err)
	}
	unlock, err := AcquireLock(env)
	if err != nil {
		t.Fatalf("dead lock owner was not reclaimed: %v", err)
	}
	if _, err := AcquireLock(env); err == nil {
		t.Fatal("second caller acquired an active lock")
	}
	unlock()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var released lockRecord
	if json.Unmarshal(body, &released) != nil || released.Status != "released" {
		t.Fatalf("lock was not marked released: %s", body)
	}
	reacquired, err := AcquireLock(env)
	if err != nil {
		t.Fatalf("released lock could not be reacquired: %v", err)
	}
	reacquired()
}

func TestAcquireLockChecksLegacyPIDProcessIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PID identity validation is Linux-specific")
	}
	env := testCoreEnvironment(t)
	if err := EnsureRuntimeDirs(env); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.DataDir, "operation.lock")
	live, _ := json.Marshal(lockRecord{
		ID: "legacy", PID: os.Getpid(), BootID: currentBootID(),
		ProcessStart: processStartTime(os.Getpid()), CreatedAt: time.Now().UTC(),
	})
	if err := os.WriteFile(path, live, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(env); err == nil {
		t.Fatal("live legacy PID owner was ignored")
	}

	var reused lockRecord
	if err := json.Unmarshal(live, &reused); err != nil {
		t.Fatal(err)
	}
	reused.ProcessStart = "different-process-start"
	reusedBody, _ := json.Marshal(reused)
	if err := os.WriteFile(path, reusedBody, 0640); err != nil {
		t.Fatal(err)
	}
	unlock, err := AcquireLock(env)
	if err != nil {
		t.Fatalf("reused PID was mistaken for the original owner: %v", err)
	}
	unlock()
}

func testCoreEnvironment(t *testing.T) Environment {
	t.Helper()
	root := t.TempDir()
	return Environment{
		Version: "test", ProtocolVersion: "1", BuildID: "test",
		DataDir:   filepath.Join(root, "lib"),
		LogDir:    filepath.Join(root, "log"),
		ConfigDir: filepath.Join(root, "etc"),
		HostRoot:  root,
	}
}
