// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Operator Pages LLC
// Date: 2026-11-22

package ccs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	ErrOutOfOrder     = errors.New("out of order: required prior step missing")
	ErrMalformedInput = errors.New("malformed or empty input")
	ErrMissingConfig  = errors.New("missing configuration")
	ErrTampered       = errors.New("tampered record")
)

// StubModule is a minimal deterministic implementation for test vectors.
// Thresholds are hard-coded here only for the skeleton; production must load versioned config.
type StubModule struct {
	Threshold float64
	assessed  bool
	recorded  bool
}

func NewStub() *StubModule {
	return &StubModule{Threshold: 0.8}
}

func (m *StubModule) Assess(signal CollapseSignal) (SurvivalAction, error) {
	if signal.ContextHash == "" || len(signal.Metrics) == 0 {
		return SurvivalAction{}, ErrMalformedInput
	}
	if m.Threshold == 0 {
		return SurvivalAction{}, ErrMissingConfig
	}

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
	m.assessed = true
	return action, nil
}

func (m *StubModule) Record(action SurvivalAction, outcome []byte) (EvidencePack, error) {
	if !m.assessed {
		return EvidencePack{}, ErrOutOfOrder
	}
	if action.Step == "" || len(action.Payload) == 0 {
		return EvidencePack{}, ErrMalformedInput
	}

	h := sha256.Sum256(append([]byte(action.Step), outcome...))
	pack := EvidencePack{
		SignalHash:  "stub-signal",
		Actions:     []SurvivalAction{action},
		OutcomeHash: hex.EncodeToString(h[:]),
		Chain:       h[:],
	}
	m.recorded = true
	return pack, nil
}

func (m *StubModule) Replay(pack EvidencePack) (bool, error) {
	if !m.recorded && len(pack.Actions) == 0 {
		return false, ErrOutOfOrder
	}
	if len(pack.Actions) == 0 || pack.OutcomeHash == "" || len(pack.Chain) == 0 {
		return false, ErrMalformedInput
	}
	action := pack.Actions[0]
	h := sha256.Sum256(append([]byte(action.Step), []byte("ok")...))
	if hex.EncodeToString(h[:]) != pack.OutcomeHash {
		return false, ErrTampered
	}
	return true, nil
}
