package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Context struct {
	context.Context
	Env Environment
	Log *RunLog
}

func Execute(parent context.Context, registry *Registry, env Environment, req Request) Result {
	start := time.Now()
	if req.RequestID == "" {
		req.RequestID = NewRequestID()
	}
	if req.ProtocolVersion == "" {
		req.ProtocolVersion = env.ProtocolVersion
	}
	if req.Source == "" {
		req.Source = "unknown"
	}

	scenario, ok := registry.FindAction(req.Action)
	if !ok {
		return finish(start, Result{
			ProtocolVersion: env.ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          StatusFailed,
			Action:          req.Action,
			Error:           &ErrorInfo{Code: "UNKNOWN_ACTION", Message: "Action is not registered"},
			ExitCode:        ExitInvalidCommand,
		})
	}

	inputs, missing, err := ValidateInputs(scenario, req.Inputs)
	if err != nil {
		return finish(start, Result{
			ProtocolVersion: env.ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          StatusFailed,
			Action:          scenario.ID,
			Error:           &ErrorInfo{Code: "INVALID_INPUT", Message: err.Error()},
			ExitCode:        ExitInvalidCommand,
		})
	}
	if len(missing) > 0 {
		return finish(start, Result{
			ProtocolVersion: env.ProtocolVersion,
			RequestID:       req.RequestID,
			Status:          StatusInputRequired,
			Action:          scenario.ID,
			Fields:          missing,
			ExitCode:        ExitInputRequired,
		})
	}

	if scenario.Risk == RiskDangerous && !req.Test {
		hash := planHash(scenario, inputs)
		if req.Approval == nil {
			record, issueErr := IssueApproval(env, scenario.ID, hash)
			if issueErr != nil {
				return finish(start, Result{
					ProtocolVersion: env.ProtocolVersion,
					RequestID:       req.RequestID,
					Status:          StatusFailed,
					Action:          scenario.ID,
					Error:           &ErrorInfo{Code: "APPROVAL_STORE_FAILED", Message: issueErr.Error()},
					ExitCode:        ExitGeneralFailure,
				})
			}
			return finish(start, Result{
				ProtocolVersion: env.ProtocolVersion,
				RequestID:       req.RequestID,
				Status:          StatusApprovalRequired,
				Action:          scenario.ID,
				Risk:            scenario.Risk,
				ApprovalID:      record.ID,
				PlanHash:        hash,
				ExpiresAt:       record.ExpiresAt.Format(time.RFC3339),
				Plan:            scenario.Steps,
				ExitCode:        ExitApprovalRequired,
			})
		}
		approvalCleanup, approvalErr := ConsumeApproval(env, req.Approval.ApprovalID, scenario.ID, hash)
		if approvalErr != nil {
			return finish(start, Result{
				ProtocolVersion: env.ProtocolVersion,
				RequestID:       req.RequestID,
				Status:          StatusFailed,
				Action:          scenario.ID,
				Error:           &ErrorInfo{Code: "APPROVAL_INVALID", Message: approvalErr.Error()},
				ExitCode:        ExitVerificationFailed,
			})
		}
		defer approvalCleanup()
	}

	_ = EnsureRuntimeDirs(env)
	runLog := NewRunLog(env, req.RequestID, scenario.ID)
	ctx := Context{Context: parent, Env: env, Log: runLog}
	runLog.Write("action=%s source=%s test=%v", scenario.ID, req.Source, req.Test)

	var unlock func()
	if !scenario.ReadOnly && !req.Test {
		var lockErr error
		unlock, lockErr = AcquireLock(env)
		if lockErr != nil {
			res := Result{
				ProtocolVersion: env.ProtocolVersion,
				RequestID:       req.RequestID,
				Status:          StatusFailed,
				Action:          scenario.ID,
				Error:           &ErrorInfo{Code: "ANOTHER_OPERATION_RUNNING", Message: lockErr.Error()},
				ExitCode:        ExitAnotherOperationRunning,
				LogReference:    runLog.Reference,
			}
			return finishAndRecord(start, env, req, res)
		}
		defer unlock()
	}

	result := scenario.Handler(ctx, req, inputs)
	result.ProtocolVersion = env.ProtocolVersion
	result.RequestID = req.RequestID
	result.Action = scenario.ID
	if result.LogReference == "" {
		result.LogReference = runLog.Reference
	}
	if result.ExitCode == 0 && result.Status != StatusSuccess {
		result.ExitCode = ExitGeneralFailure
	}
	if req.Test && result.Status == StatusSuccess && !scenario.ReadOnly {
		result.ExitCode = ExitTestModeCompleted
	}
	runLog.Write("status=%s changed=%v", result.Status, result.Changed)
	runLog.Close()
	return finishAndRecord(start, env, req, result)
}

func finishAndRecord(start time.Time, env Environment, req Request, result Result) Result {
	result = finish(start, result)
	_ = AppendHistory(env, HistoryEntry{
		ID:        result.LogReference,
		Time:      time.Now(),
		Action:    result.Action,
		Status:    result.Status,
		Changed:   result.Changed,
		Source:    req.Source,
		RequestID: req.RequestID,
	})
	return result
}

func finish(start time.Time, result Result) Result {
	result.DurationMS = time.Since(start).Milliseconds()
	if result.ExitCode == 0 && result.Status == StatusSuccess {
		result.ExitCode = ExitSuccess
	}
	return result
}

func planHash(s Scenario, inputs map[string]interface{}) string {
	payload, err := json.Marshal(struct {
		Action string                 `json:"action"`
		Steps  []StepSpec             `json:"steps"`
		Inputs map[string]interface{} `json:"inputs"`
	}{Action: s.ID, Steps: s.Steps, Inputs: inputs})
	if err != nil {
		payload = []byte(fmt.Sprintf("%s:%v", s.ID, s.Steps))
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func EnsureRuntimeDirs(env Environment) error {
	paths := []string{
		env.DataDir,
		env.LogDir,
		env.ConfigDir,
		filepath.Join(env.DataDir, "backups"),
		filepath.Join(env.DataDir, "recovery"),
		filepath.Join(env.DataDir, "approvals"),
		filepath.Join(env.LogDir, "runs"),
	}
	for _, path := range paths {
		if err := os.MkdirAll(path, 0750); err != nil {
			return err
		}
	}
	_ = os.Chmod(filepath.Join(env.DataDir, "approvals"), 0700)
	return nil
}
