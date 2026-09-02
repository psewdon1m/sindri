package core

import "time"

const (
	ProtocolVersion = "1"
)

const (
	ExitSuccess                 = 0
	ExitGeneralFailure          = 1
	ExitInvalidCommand          = 2
	ExitUnsupportedOS           = 3
	ExitInsufficientPrivileges  = 4
	ExitPrecheckFailed          = 5
	ExitCancelledByUser         = 6
	ExitApprovalRequired        = 7
	ExitAnotherOperationRunning = 8
	ExitPartialSuccess          = 9
	ExitRebootRequired          = 10
	ExitInputRequired           = 11
	ExitTestModeCompleted       = 12
	ExitTimeout                 = 13
	ExitVerificationFailed      = 14
	ExitRecoveryStateMissing    = 15
	ExitRecoveryStateCorrupted  = 16
	ExitProviderActionRequired  = 17
	ExitManagedScopeViolation   = 18
)

type Risk string

const (
	RiskRead      Risk = "read"
	RiskChange    Risk = "change"
	RiskDangerous Risk = "dangerous"
)

type Status string

const (
	StatusSuccess          Status = "success"
	StatusFailed           Status = "failed"
	StatusPartial          Status = "partial"
	StatusInputRequired    Status = "input_required"
	StatusApprovalRequired Status = "approval_required"
)

type InputType string

const (
	InputString  InputType = "string"
	InputInteger InputType = "integer"
	InputChoice  InputType = "choice"
	InputBoolean InputType = "boolean"
	InputPath    InputType = "path"
	InputSecret  InputType = "secret"
)

type InputSpec struct {
	Name     string      `json:"name"`
	Position int         `json:"position,omitempty"`
	Type     InputType   `json:"type"`
	Minimum  int         `json:"minimum,omitempty"`
	Maximum  int         `json:"maximum,omitempty"`
	Required bool        `json:"required"`
	Prompt   string      `json:"prompt,omitempty"`
	Values   []string    `json:"values,omitempty"`
	Default  interface{} `json:"default,omitempty"`
	Secret   bool        `json:"secret,omitempty"`
}

type StepSpec struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type StepResult struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type Approval struct {
	ApprovalID           string `json:"approval_id,omitempty"`
	PlanHash             string `json:"plan_hash,omitempty"`
	ConfirmationPhrase   string `json:"confirmation_phrase,omitempty"`
	HostnameConfirmation string `json:"hostname_confirmation,omitempty"`
}

type Request struct {
	ProtocolVersion string                 `json:"protocol_version,omitempty"`
	RequestID       string                 `json:"request_id,omitempty"`
	Action          string                 `json:"action"`
	Test            bool                   `json:"test,omitempty"`
	Inputs          map[string]interface{} `json:"inputs,omitempty"`
	Approval        *Approval              `json:"approval,omitempty"`
	Source          string                 `json:"-"`
}

type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type FieldRequirement struct {
	Name     string      `json:"name"`
	Type     InputType   `json:"type"`
	Minimum  int         `json:"minimum,omitempty"`
	Maximum  int         `json:"maximum,omitempty"`
	Required bool        `json:"required"`
	Prompt   string      `json:"prompt,omitempty"`
	Values   []string    `json:"values,omitempty"`
	Default  interface{} `json:"default,omitempty"`
}

type Result struct {
	ProtocolVersion string                 `json:"protocol_version,omitempty"`
	RequestID       string                 `json:"request_id,omitempty"`
	Status          Status                 `json:"status"`
	Action          string                 `json:"action,omitempty"`
	Changed         bool                   `json:"changed"`
	Message         string                 `json:"message,omitempty"`
	DurationMS      int64                  `json:"duration_ms,omitempty"`
	LogReference    string                 `json:"log_reference,omitempty"`
	Fields          []FieldRequirement     `json:"fields,omitempty"`
	Risk            Risk                   `json:"risk,omitempty"`
	ApprovalID      string                 `json:"approval_id,omitempty"`
	PlanHash        string                 `json:"plan_hash,omitempty"`
	ExpiresAt       string                 `json:"expires_at,omitempty"`
	Plan            []StepSpec             `json:"plan,omitempty"`
	Steps           []StepResult           `json:"steps,omitempty"`
	Data            map[string]interface{} `json:"data,omitempty"`
	Error           *ErrorInfo             `json:"error,omitempty"`
	ExitCode        int                    `json:"-"`
}

type Handler func(ctx Context, req Request, inputs map[string]interface{}) Result

type Scenario struct {
	ID               string      `json:"id"`
	APIVersion       int         `json:"api_version"`
	CLIPath          []string    `json:"cli_path"`
	CLIAliases       [][]string  `json:"cli_aliases,omitempty"`
	Usage            string      `json:"usage"`
	Title            string      `json:"title"`
	Description      string      `json:"description"`
	SupportedSystems []string    `json:"supported_systems"`
	Inputs           []InputSpec `json:"inputs"`
	Risk             Risk        `json:"risk"`
	ReadOnly         bool        `json:"read_only"`
	Interactive      bool        `json:"interactive,omitempty"`
	Steps            []StepSpec  `json:"steps"`
	Handler          Handler     `json:"-"`
}

type HistoryEntry struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Action    string    `json:"action"`
	Status    Status    `json:"status"`
	Changed   bool      `json:"changed"`
	Source    string    `json:"source"`
	RequestID string    `json:"request_id"`
}
