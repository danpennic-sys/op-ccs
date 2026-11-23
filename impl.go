// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Operator Pages LLC
// Date: 2026-11-22

package ccs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrOutOfOrder     = errors.New("out of order: required prior step missing")
	ErrMalformedInput = errors.New("malformed or empty input")
	ErrMissingConfig  = errors.New("missing configuration")
	ErrTampered       = errors.New("tampered record")
)

// StubModule is a minimal deterministic implementation for test vectors.
// Threshold zero means missing config (never legitimate).
// Hash covers step | context | input-payload | outcome (canonical, sorted, no wall-clock).
// Input is included so mutate_input after Record is detected as tamper.
type StubModule struct {
	Threshold float64
	assessed  bool
	recorded  bool
}

func NewStub() *StubModule {
	return &StubModule{Threshold: 0.8}
}

func (m *StubModule) Assess(signal CollapseSignal) (SurvivalAction, error) {
	if m.assessed {
		return SurvivalAction{}, ErrOutOfOrder
	}
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
		ActionID:  "act-fixed", // fixed for determinism; production uses versioned id
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

// canonicalHash includes the input payload so that mutations to recorded input are detected.
func canonicalHash(step, context string, input, outcome []byte) string {
	parts := []string{step, context, string(input), string(outcome)}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

func (m *StubModule) Record(action SurvivalAction, outcome []byte) (EvidencePack, error) {
	if !m.assessed {
		return EvidencePack{}, ErrOutOfOrder
	}
	if action.Step == "" || len(action.Payload) == 0 {
		return EvidencePack{}, ErrMalformedInput
	}

	hash := canonicalHash(action.Step, "stub-context", action.Payload, outcome)
	pack := EvidencePack{
		SignalHash:  "stub-signal",
		Actions:     []SurvivalAction{action},
		OutcomeHash: hash,
		Chain:       []byte(hash),
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
	expected := canonicalHash(action.Step, "stub-context", action.Payload, []byte("ok"))
	if expected != pack.OutcomeHash || string(pack.Chain) != pack.OutcomeHash {
		return false, ErrTampered
	}
	return true, nil
}
