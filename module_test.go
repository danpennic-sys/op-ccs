package ccs

import (
	"testing"
	"time"
)

func TestBelowThreshold_PassThrough(t *testing.T) {
	m := NewStub()
	signal := CollapseSignal{
		Timestamp: time.Now().UTC(),
		Metrics:   map[string]float64{"load": 0.3},
		Constraints: []string{"evidence_required"},
		ContextHash: "ctx-below",
	}

	action, err := m.Assess(signal)
	if err != nil {
		t.Fatal(err)
	}
	if action.Step != "ACT" {
		t.Fatalf("expected ACT, got %s", action.Step)
	}
	if action.EvidenceRef != "below-threshold" {
		t.Fatalf("unexpected evidence ref: %s", action.EvidenceRef)
	}

	pack, err := m.Record(action, []byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Actions) != 1 || pack.Actions[0].Step != "ACT" {
		t.Fatal("pack missing ACT")
	}

	ok, err := m.Replay(pack)
	if err != nil || !ok {
		t.Fatal("replay failed")
	}
}

func TestAboveThreshold_ForcedAbort(t *testing.T) {
	m := NewStub()
	signal := CollapseSignal{
		Timestamp: time.Now().UTC(),
		Metrics:   map[string]float64{"load": 0.95},
		Constraints: []string{"time_bound", "evidence_required"},
		ContextHash: "ctx-above",
	}

	action, err := m.Assess(signal)
	if err != nil {
		t.Fatal(err)
	}
	if action.Step != "ABORT" {
		t.Fatalf("expected ABORT, got %s", action.Step)
	}
	if action.EvidenceRef != "collapse-triggered" {
		t.Fatalf("unexpected evidence ref: %s", action.EvidenceRef)
	}

	pack, err := m.Record(action, []byte("aborted"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Actions) != 1 || pack.Actions[0].Step != "ABORT" {
		t.Fatal("pack missing ABORT")
	}

	ok, err := m.Replay(pack)
	if err != nil || !ok {
		t.Fatal("replay failed")
	}
}

func TestReplay_Deterministic(t *testing.T) {
	m := NewStub()
	signal := CollapseSignal{
		Timestamp: time.Date(2026, 11, 22, 16, 0, 0, 0, time.UTC),
		Metrics:   map[string]float64{"load": 0.9},
		ContextHash: "fixed",
	}

	a1, _ := m.Assess(signal)
	p1, _ := m.Record(a1, []byte("ok"))

	a2, _ := m.Assess(signal)
	p2, _ := m.Record(a2, []byte("ok"))

	if a1.Step != a2.Step || p1.OutcomeHash != p2.OutcomeHash {
		t.Fatal("non-deterministic output")
	}
}
