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
	Timestamp    string             `json:"timestamp"`
	Metrics      map[string]float64 `json:"metrics"`
	ContextHash  string             `json:"context_hash"`
	ZeroThreshold bool              `json:"zero_threshold,omitempty"`
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

			case "replay-determinism":
				var in struct {
					Signal  SignalInput `json:"signal"`
					Outcome string      `json:"outcome"`
				}
				json.Unmarshal(v.Input, &in)
				ts, _ := time.Parse(time.RFC3339, in.Signal.Timestamp)
				signal := CollapseSignal{
					Timestamp:   ts,
					Metrics:     in.Signal.Metrics,
					ContextHash: in.Signal.ContextHash,
				}
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
				ok, err := m.Replay(p1)
				if err != nil || !ok {
					t.Fatal("replay failed")
				}

			case "boundary-empty-metrics", "boundary-empty-context":
				var in struct {
					Signal SignalInput `json:"signal"`
				}
				json.Unmarshal(v.Input, &in)
				ts, _ := time.Parse(time.RFC3339, in.Signal.Timestamp)
				signal := CollapseSignal{
					Timestamp:   ts,
					Metrics:     in.Signal.Metrics,
					ContextHash: in.Signal.ContextHash,
				}
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
				ts, _ := time.Parse(time.RFC3339, in.Signal.Timestamp)
				signal := CollapseSignal{
					Timestamp:   ts,
					Metrics:     in.Signal.Metrics,
					ContextHash: in.Signal.ContextHash,
				}
				_, err := m.Assess(signal)
				if err == nil || err.Error() != v.ExpectedError {
					t.Fatalf("expected %q, got %v", v.ExpectedError, err)
				}

			case "tamper-modified-outcome-hash":
				var in struct {
					Signal  SignalInput `json:"signal"`
					Outcome string      `json:"outcome"`
					Tamper  bool        `json:"tamper"`
				}
				json.Unmarshal(v.Input, &in)
				ts, _ := time.Parse(time.RFC3339, in.Signal.Timestamp)
				signal := CollapseSignal{
					Timestamp:   ts,
					Metrics:     in.Signal.Metrics,
					ContextHash: in.Signal.ContextHash,
				}
				action, err := m.Assess(signal)
				if err != nil {
					t.Fatal(err)
				}
				pack, err := m.Record(action, []byte(in.Outcome))
				if err != nil {
					t.Fatal(err)
				}
				if in.Tamper {
					pack.OutcomeHash = "deadbeef"
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
