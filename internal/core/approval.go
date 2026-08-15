package core

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const approvalLifetime = 5 * time.Minute

var approvalIDPattern = regexp.MustCompile(`^approval-[a-f0-9]{8}$`)

type approvalRecord struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	PlanHash  string    `json:"plan_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

func IssueApproval(env Environment, action, planHash string) (approvalRecord, error) {
	if err := EnsureRuntimeDirs(env); err != nil {
		return approvalRecord{}, err
	}
	directory := filepath.Join(env.DataDir, "approvals")
	pruneExpiredApprovals(directory)
	record := approvalRecord{
		ID:        "approval-" + NewShortID(),
		Action:    action,
		PlanHash:  planHash,
		ExpiresAt: time.Now().UTC().Add(approvalLifetime),
	}
	path := filepath.Join(directory, record.ID+".json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return approvalRecord{}, err
	}
	encodeErr := json.NewEncoder(file).Encode(record)
	closeErr := file.Close()
	if encodeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if encodeErr != nil {
			return approvalRecord{}, encodeErr
		}
		return approvalRecord{}, closeErr
	}
	return record, nil
}

func ConsumeApproval(env Environment, id, action, planHash string) (func(), error) {
	if !approvalIDPattern.MatchString(id) {
		return nil, errors.New("approval ID is invalid")
	}
	directory := filepath.Join(env.DataDir, "approvals")
	path := filepath.Join(directory, id+".json")
	claimed := path + ".claimed-" + NewShortID()
	if err := os.Rename(path, claimed); err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("approval was not issued or was already used")
		}
		return nil, err
	}
	cleanup := func() { _ = os.Remove(claimed) }
	body, err := os.ReadFile(claimed)
	if err != nil {
		cleanup()
		return nil, err
	}
	var record approvalRecord
	if err := json.Unmarshal(body, &record); err != nil {
		cleanup()
		return nil, errors.New("approval record is corrupted")
	}
	if record.ID != id || record.Action != action || record.PlanHash != planHash {
		cleanup()
		return nil, errors.New("approval does not match the requested action and plan")
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		cleanup()
		return nil, errors.New("approval has expired")
	}
	return cleanup, nil
}

func pruneExpiredApprovals(directory string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		body, readErr := os.ReadFile(path)
		var record approvalRecord
		if readErr != nil || json.Unmarshal(body, &record) != nil || now.After(record.ExpiresAt) {
			_ = os.Remove(path)
		}
	}
}
