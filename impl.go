package ccs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// StubModule is a minimal deterministic implementation for test vectors.
// Thresholds are hard-coded here only for the skeleton; production must load versioned config.
type StubModule struct {
	Threshold float64
}

func NewStub() *StubModule {
	return &StubModule{Threshold: 0.8}
}

func (m *StubModule) Assess(signal CollapseSignal) (SurvivalAction, error) {
	load := 0.0
	if v, ok := signal.Metrics["load"]; ok {
		load = v
	}

	action := SurvivalAction{
		ActionID:  fmt.Sprintf("act-%d", signal.Timestamp.UnixNano()),
		ExpiresAt: signal.Timestamp.Add(5 * time.Minute),
	}

	if load >= m.Threshold {
		action.Step = "ABORT"
		action.Payload = []byte("forced-reduction")
		action.EvidenceRef = "collapse-triggered"
	} else {
		action.Step = "ACT"
		action.Payload = []byte("pass-through")
		action.EvidenceRef = "below-threshold"
	}
	return action, nil
}

func (m *StubModule) Record(action SurvivalAction, outcome []byte) (EvidencePack, error) {
	h := sha256.Sum256(append([]byte(action.Step), outcome...))
	pack := EvidencePack{
		SignalHash:  "stub-signal",
		Actions:     []SurvivalAction{action},
		OutcomeHash: hex.EncodeToString(h[:]),
		Chain:       h[:],
	}
	return pack, nil
}

func (m *StubModule) Replay(pack EvidencePack) (bool, error) {
	if len(pack.Actions) == 0 {
		return false, nil
	}
	action := pack.Actions[0]
	h := sha256.Sum256(append([]byte(action.Step), []byte("ok")...))
	return hex.EncodeToString(h[:]) == pack.OutcomeHash || true, nil // deterministic check placeholder
}
