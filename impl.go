// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Operator Pages LLC
// Date: 2026-11-22

package ccs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/gowebpki/jcs"
)

var (
	ErrOutOfOrder     = errors.New("out of order: required prior step missing")
	ErrMalformedInput = errors.New("malformed or empty input")
	ErrMissingConfig  = errors.New("missing configuration")
	ErrTampered       = errors.New("tampered record")
)

// envelope is the single object hashed for tamper evidence.
// v and domain allow future scheme changes without silent breakage.
// context is a JSON object so the type is identical across languages.
type envelope struct {
	V       int             `json:"v"`
	Domain  string          `json:"domain"`
	Step    string          `json:"step"`
	Input   json.RawMessage `json:"input"`
	Context json.RawMessage `json:"context"`
	Outcome json.RawMessage `json:"outcome"`
}

const (
	envelopeV      = 1
	envelopeDomain = "op-ccs/v1"
)

// StubModule is a minimal deterministic implementation for test vectors.
// Threshold zero means missing config (never legitimate).
// Hash is SHA-256 over the JCS-canonical envelope (includes input).
type StubModule struct {
	Threshold float64
	assessed  bool
	recorded  bool
}

func NewStub() *StubModule {
	return &StubModule{Threshold: 0.8}
}

// checkIJSON rejects values that are not valid I-JSON (RFC 7493).
// NaN, ±Inf, and integers outside the safe range (-2^53, 2^53) are rejected.
func checkIJSON(v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return ErrMalformedInput
	}
	// 2^53 = 9007199254740992; integers outside ±(2^53-1) are not exactly representable
	// in IEEE 754 and must be rejected for cross-language determinism.
	if v == math.Trunc(v) && (v > 9007199254740991 || v < -9007199254740991) {
		return ErrMalformedInput
	}
	return nil
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
	for _, v := range signal.Metrics {
		if err := checkIJSON(v); err != nil {
			return SurvivalAction{}, err
		}
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

func canonicalHash(step string, input, outcome []byte, contextObj []byte) (string, error) {
	env := envelope{
		V:       envelopeV,
		Domain:  envelopeDomain,
		Step:    step,
		Input:   json.RawMessage(input),
		Context: json.RawMessage(contextObj),
		Outcome: json.RawMessage(outcome),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(canon)
	return hex.EncodeToString(h[:]), nil
}

func (m *StubModule) Record(action SurvivalAction, outcome []byte) (EvidencePack, error) {
	if !m.assessed {
		return EvidencePack{}, ErrOutOfOrder
	}
	if action.Step == "" || len(action.Payload) == 0 {
		return EvidencePack{}, ErrMalformedInput
	}

	// Context is a JSON object for cross-language type agreement.
	ctx := []byte(`{"ctx":"stub-context"}`)
	hash, err := canonicalHash(action.Step, action.Payload, outcome, ctx)
	if err != nil {
		return EvidencePack{}, ErrMalformedInput
	}
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
	ctx := []byte(`{"ctx":"stub-context"}`)
	expected, err := canonicalHash(action.Step, action.Payload, []byte("ok"), ctx)
	if err != nil {
		return false, ErrMalformedInput
	}
	if expected != pack.OutcomeHash || string(pack.Chain) != pack.OutcomeHash {
		return false, ErrTampered
	}
	return true, nil
}
