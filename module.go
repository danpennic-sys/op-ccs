package ccs

import (
	"time"
)

// CollapseSignal is the only input the module accepts.
// All fields must be observable and replayable.
type CollapseSignal struct {
	Timestamp   time.Time
	Metrics     map[string]float64 // latency, error_rate, queue_depth, decision_count, etc.
	Constraints []string           // time_bound, irreversible, evidence_required, ...
	ContextHash string
}

// SurvivalAction is the only output.
type SurvivalAction struct {
	ActionID    string
	Step        string // SEE | SET | ACT | VERIFY | RECORD | ABORT | DEFER
	Payload     []byte
	EvidenceRef string
	ExpiresAt   time.Time
}

// EvidencePack is the required artifact of every transition.
type EvidencePack struct {
	SignalHash  string
	Actions     []SurvivalAction
	OutcomeHash string
	Chain       []byte
}

// Module is the locked contract.
type Module interface {
	Assess(signal CollapseSignal) (SurvivalAction, error)
	Record(action SurvivalAction, outcome []byte) (EvidencePack, error)
	Replay(pack EvidencePack) (bool, error)
}
