// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Operator Pages LLC
// Date: 2026-11-22

package ccs

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type Vector struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Input         json.RawMessage `json:"input"`
	Expected      json.RawMessage `json:"expected,omitempty"`
	ExpectedError string          `json:"expected_error,omitempty"`
}

type SignalInput struct {
	Timestamp     string             `json:"timestamp"`
	Metrics       map[string]float64 `json:"metrics"`
	ContextHash   string             `json:"context_hash"`
	ZeroThreshold bool               `json:"zero_threshold,omitempty"`
}

type ActionInput struct {
	Step    string `json:"step"`
	Payload string `json:"payload"`
}

func loadVectors(t *testing.T) []Vector {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []Vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func parseSignal(in SignalInput) CollapseSignal {
	ts, _ := time.Parse(time.RFC3339, in.Timestamp)
	return CollapseSignal{
		Timestamp:   ts,
		Metrics:     in.Metrics,
		ContextHash: in.ContextHash,
	}
}

func TestVectors(t *testing.T) {
	vectors := loadVectors(t)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			m := NewStub()

			switch v.Name {
			case "forced-sequence-record-before-assess":
				var in struct {
					Action  ActionInput `json:"action"`
					Outcome string      `json:"outcome"`
				}
				json.Unmarshal(v.Input, &in)
				action := SurvivalAction{Step: in.Action.Step, Payload: []byte(in.Action.Payload)}
				_, err := m.Record(action, []byte(in.Outcome))
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			case "forced-sequence-replay-before-record":
				var in struct {
					Pack EvidencePack `json:"pack"`
				}
				json.Unmarshal(v.Input, &in)
				_, err := m.Replay(in.Pack)
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			case "forced-sequence-assess-twice":
				var in struct {
					Signal SignalInput `json:"signal"`
				}
				json.Unmarshal(v.Input, &in)
				signal := parseSignal(in.Signal)
				_, err := m.Assess(signal)
				if err != nil {
					t.Fatal(err)
				}
				_, err = m.Assess(signal)
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			case "forced-sequence-replay-after-failed-record":
				var in struct {
					Signal SignalInput `json:"signal"`
				}
				json.Unmarshal(v.Input, &in)
				signal := parseSignal(in.Signal)
				_, err := m.Assess(signal)
				if err != nil {
					t.Fatal(err)
				}
				_, err = m.Record(SurvivalAction{}, []byte(""))
				if err == nil {
					t.Fatal("expected record to fail")
				}
				_, err = m.Replay(EvidencePack{})
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			case "replay-determinism":
				var in struct {
					Signal  SignalInput `json:"signal"`
					Outcome string      `json:"outcome"`
				}
				json.Unmarshal(v.Input, &in)
				signal := parseSignal(in.Signal)
				a1, err := m.Assess(signal)
				if err != nil {
					t.Fatal(err)
				}
				p1, err := m.Record(a1, []byte(in.Outcome))
				if err != nil {
					t.Fatal(err)
				}

				m2 := NewStub()
				a2, _ := m2.Assess(signal)
				p2, _ := m2.Record(a2, []byte(in.Outcome))

				if a1.Step != a2.Step || p1.OutcomeHash != p2.OutcomeHash {
					t.Fatal("non-deterministic")
				}
				ok1, err := m.Replay(p1)
				if err != nil || !ok1 {
					t.Fatal("first replay failed")
				}
				ok2, err := m.Replay(p1)
				if err != nil || !ok2 {
					t.Fatal("second replay failed")
				}

			case "boundary-empty-metrics", "boundary-empty-context":
				var in struct {
					Signal SignalInput `json:"signal"`
				}
				json.Unmarshal(v.Input, &in)
				signal := parseSignal(in.Signal)
				_, err := m.Assess(signal)
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			case "boundary-missing-config":
				var in struct {
					Signal        SignalInput `json:"signal"`
					ZeroThreshold bool        `json:"zero_threshold"`
				}
				json.Unmarshal(v.Input, &in)
				if in.ZeroThreshold {
					m.Threshold = 0
				}
				signal := parseSignal(in.Signal)
				_, err := m.Assess(signal)
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			case "tamper-modified-outcome-hash", "tamper-modified-context", "tamper-truncated-chain", "tamper-dropped-field":
				var in struct {
					Signal  SignalInput `json:"signal"`
					Outcome string      `json:"outcome"`
					Tamper  string      `json:"tamper"`
				}
				json.Unmarshal(v.Input, &in)
				signal := parseSignal(in.Signal)
				action, err := m.Assess(signal)
				if err != nil {
					t.Fatal(err)
				}
				pack, err := m.Record(action, []byte(in.Outcome))
				if err != nil {
					t.Fatal(err)
				}
				switch in.Tamper {
				case "outcome_hash":
					pack.OutcomeHash = "deadbeef"
				case "context":
					pack.SignalHash = "tampered"
				case "truncate":
					if len(pack.Chain) > 4 {
						pack.Chain = pack.Chain[:4]
					}
				case "drop":
					pack.Actions = nil
				}
				_, err = m.Replay(pack)
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			default:
				t.Fatalf("unknown vector: %s", v.Name)
			}
		})
	}
}
