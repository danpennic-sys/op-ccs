// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Operator Pages LLC
// Date: 2026-11-27

package ccs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

var (
	ErrOutOfOrder         = errors.New("out of order: required prior step missing")
	ErrMalformedInput     = errors.New("malformed or empty input")
	ErrMissingConfig      = errors.New("missing configuration")
	ErrUnsupportedVersion = errors.New("unsupported config version")
	ErrTampered           = errors.New("tampered record")
)

// Config is the versioned configuration contract for the scoring module.
type Config struct {
	Version   string
	Threshold float64
	Metrics   map[string]float64 // name -> weight
}

// ConfigV1 is the only supported version string.
const ConfigV1 = "op-ccs-config/v1"

// configSnapshot is an immutable view of a validated config.
// keys are sorted for deterministic summation order.
type configSnapshot struct {
	version   string
	threshold float64
	weights   map[string]float64
	keys      []string
}

// RealModule implements Module and the versioned Config contract.
// Production path: must be Configure'd before Assess.
type RealModule struct {
	mu       sync.RWMutex
	config   *configSnapshot // nil until successfully configured
	assessed bool
	recorded bool
}

// New returns an unconfigured module.
func New() *RealModule {
	return &RealModule{}
}

// Configure validates c and installs it as the active snapshot.
// On any error the previous snapshot (if any) is left unchanged.
func (m *RealModule) Configure(c Config) error {
	if c.Version == "" {
		return ErrMissingConfig
	}
	if c.Version != ConfigV1 {
		return ErrUnsupportedVersion
	}
	// Non-finite first.
	if math.IsNaN(c.Threshold) || math.IsInf(c.Threshold, 0) {
		return ErrMalformedInput
	}
	// Threshold must be strictly positive. -0 is treated as missing.
	if c.Threshold <= 0 || math.Signbit(c.Threshold) {
		return ErrMissingConfig
	}

	if len(c.Metrics) == 0 {
		return ErrMissingConfig
	}

	weights := make(map[string]float64, len(c.Metrics))
	keys := make([]string, 0, len(c.Metrics))
	for k, w := range c.Metrics {
		if k == "" {
			return ErrMalformedInput
		}
		if math.IsNaN(w) || math.IsInf(w, 0) || w < 0 {
			return ErrMalformedInput
		}
		weights[k] = w
		keys = append(keys, k)
	}
	sort.Strings(keys)

	snap := &configSnapshot{
		version:   c.Version,
		threshold: c.Threshold,
		weights:   weights,
		keys:      keys,
	}

	m.mu.Lock()
	m.config = snap
	m.mu.Unlock()
	return nil
}

// score is the test hook that returns the raw weighted score, pass/fail, and error.
// Production Assess uses the same snapshot-once logic.
func (m *RealModule) score(metrics map[string]float64) (float64, bool, error) {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()
	if cfg == nil {
		return 0, false, ErrMissingConfig
	}
	return scoreAgainst(cfg, metrics)
}

// scoreAgainst computes the weighted score against a single snapshot.
// Reads all fields from the provided snapshot only.
func scoreAgainst(cfg *configSnapshot, metrics map[string]float64) (float64, bool, error) {
	for _, v := range metrics {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false, ErrMalformedInput
		}
	}
	var sum float64
	for _, k := range cfg.keys {
		w := cfg.weights[k]
		s := metrics[k] // absent -> 0
		sum += s * w
	}
	pass := sum >= cfg.threshold
	return sum, pass, nil
}

// Assess implements Module.Assess.
// Metrics from the signal are used directly (unknown keys ignored, missing contribute 0).
// Non-finite values are rejected.
func (m *RealModule) Assess(signal CollapseSignal) (SurvivalAction, error) {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()
	if cfg == nil {
		return SurvivalAction{}, ErrMissingConfig
	}
	if m.assessed {
		return SurvivalAction{}, ErrOutOfOrder
	}
	if signal.ContextHash == "" || len(signal.Metrics) == 0 {
		return SurvivalAction{}, ErrMalformedInput
	}

	_, pass, err := scoreAgainst(cfg, signal.Metrics)
	if err != nil {
		return SurvivalAction{}, err
	}

	action := SurvivalAction{
		ActionID:  "act-fixed", // fixed for determinism; production uses versioned id
		ExpiresAt: signal.Timestamp.Add(5 * time.Minute),
	}
	if !pass {
		action.Step = "ACT"
		action.Payload = []byte("pass-through")
		action.EvidenceRef = "below-threshold"
	} else {
		action.Step = "ABORT"
		action.Payload = []byte("forced-reduction")
		action.EvidenceRef = "collapse-triggered"
	}
	m.assessed = true
	return action, nil
}

// envelope is the single object hashed for tamper evidence.
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

// canonicalHash is SHA-256 over the JCS form of the envelope.
func canonicalHash(step string, input, outcome []byte, contextObj []byte) (string, error) {
	in, err := jsonText(input)
	if err != nil {
		return "", err
	}
	out, err := jsonText(outcome)
	if err != nil {
		return "", err
	}
	if !json.Valid(contextObj) {
		return "", errors.New("context is not valid JSON")
	}
	env := envelope{
		V:       envelopeV,
		Domain:  envelopeDomain,
		Step:    step,
		Input:   in,
		Context: json.RawMessage(contextObj),
		Outcome: out,
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

func jsonText(b []byte) (json.RawMessage, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("payload is not valid UTF-8")
	}
	raw, err := json.Marshal(string(b))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func isSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// configContext builds the JSON context object that binds the active config
// into the hashed record. Includes version and sorted weights.
func configContext(cfg *configSnapshot) ([]byte, error) {
	type weightPair struct {
		Key    string  `json:"key"`
		Weight float64 `json:"weight"`
	}
	pairs := make([]weightPair, 0, len(cfg.keys))
	for _, k := range cfg.keys {
		pairs = append(pairs, weightPair{Key: k, Weight: cfg.weights[k]})
	}
	ctx := map[string]any{
		"ctx":       "op-ccs",
		"version":   cfg.version,
		"threshold": cfg.threshold,
		"weights":   pairs,
	}
	return json.Marshal(ctx)
}

func (m *RealModule) Record(action SurvivalAction, outcome []byte) (EvidencePack, error) {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()
	if cfg == nil {
		return EvidencePack{}, ErrMissingConfig
	}
	if !m.assessed {
		return EvidencePack{}, ErrOutOfOrder
	}
	if action.Step == "" || len(action.Payload) == 0 {
		return EvidencePack{}, ErrMalformedInput
	}

	ctx, err := configContext(cfg)
	if err != nil {
		return EvidencePack{}, ErrMalformedInput
	}
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

func (m *RealModule) Replay(pack EvidencePack) (bool, error) {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()
	if cfg == nil {
		return false, ErrMissingConfig
	}
	if !m.recorded && len(pack.Actions) == 0 {
		return false, ErrOutOfOrder
	}
	if len(pack.Actions) == 0 || pack.SignalHash == "" || pack.OutcomeHash == "" || len(pack.Chain) == 0 {
		return false, ErrMalformedInput
	}
	if !isSHA256Hex(pack.OutcomeHash) || !isSHA256Hex(string(pack.Chain)) {
		return false, ErrMalformedInput
	}
	action := pack.Actions[0]
	if action.Step == "" || len(action.Payload) == 0 {
		return false, ErrMalformedInput
	}
	ctx, err := configContext(cfg)
	if err != nil {
		return false, ErrMalformedInput
	}
	expected, err := canonicalHash(action.Step, action.Payload, []byte("ok"), ctx)
	if err != nil {
		return false, ErrMalformedInput
	}
	if expected != pack.OutcomeHash || string(pack.Chain) != pack.OutcomeHash || pack.SignalHash != "stub-signal" {
		return false, ErrTampered
	}
	return true, nil
}
