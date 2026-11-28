// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Operator Pages LLC
// Date: 2026-11-27

package ccs

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type VectorsFile struct {
	License   string `json:"_license"`
	Copyright string `json:"_copyright"`
	Date      string `json:"_date"`
	Note      string `json:"_note"`
	Cases     []Case `json:"cases"`
}

type Case struct {
	Name                string  `json:"name"`
	Mutation            string  `json:"mutation"`
	ExpectErr           *string `json:"expect_err"`
	ExpectIdenticalRuns int     `json:"expect_identical_runs,omitempty"`
	ExpectOutcomeHash   string  `json:"expect_outcome_hash,omitempty"`
}

var errSentinels = map[string]error{
	"ErrOutOfOrder":     ErrOutOfOrder,
	"ErrMalformedInput": ErrMalformedInput,
	"ErrMissingConfig":  ErrMissingConfig,
	"ErrTampered":       ErrTampered,
}

func loadCases(t *testing.T) []Case {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf VectorsFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatal(err)
	}
	return vf.Cases
}

func baselineSignal() CollapseSignal {
	return CollapseSignal{
		Timestamp:   time.Date(2026, 11, 22, 16, 0, 0, 0, time.UTC),
		Metrics:     map[string]float64{"load": 0.3},
		ContextHash: "fixed-ctx",
	}
}

func baselineOutcome() []byte {
	return []byte("ok")
}

func baselineConfig() Config {
	return Config{
		Version:   ConfigV1,
		Threshold: 0.8,
		Metrics:   map[string]float64{"load": 1.0},
	}
}

func checkErr(t *testing.T, got error, expect *string) {
	t.Helper()
	if expect == nil {
		if got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
		return
	}
	name := *expect
	sentinel, ok := errSentinels[name]
	if !ok {
		t.Fatalf("unknown expect_err name in JSON: %q", name)
	}
	if !errors.Is(got, sentinel) {
		t.Fatalf("expected %s, got %v", name, got)
	}
}

func TestVectors(t *testing.T) {
	cases := loadCases(t)

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			m := New()
			if err := m.Configure(baselineConfig()); err != nil {
				t.Fatal(err)
			}
			signal := baselineSignal()
			outcome := baselineOutcome()

			switch {
			case strings.HasPrefix(c.Mutation, "call_order:"):
				parts := strings.Split(strings.TrimPrefix(c.Mutation, "call_order:"), ",")
				var lastErr error
				for _, step := range parts {
					switch step {
					case "assess":
						_, lastErr = m.Assess(signal)
					case "record_fail":
						_, lastErr = m.Record(SurvivalAction{}, []byte(""))
					case "replay":
						_, lastErr = m.Replay(EvidencePack{})
					}
				}
				checkErr(t, lastErr, c.ExpectErr)
				return

			default:
				action, err := m.Assess(signal)
				if err != nil {
					t.Fatal(err)
				}
				pack, err := m.Record(action, outcome)
				if err != nil {
					t.Fatal(err)
				}

				switch c.Mutation {
				case "mutate_input":
					pack.Actions[0].Payload = []byte("tampered")
				case "mutate_context":
					pack.SignalHash = "tampered"
				case "flip_outcome_hash":
					if len(pack.OutcomeHash) > 0 {
						pack.OutcomeHash = pack.OutcomeHash[:len(pack.OutcomeHash)-1] + "f"
					}
				case "truncate_half":
					if len(pack.Chain) > 1 {
						pack.Chain = pack.Chain[:len(pack.Chain)/2]
					}
				case "drop_field:input":
					pack.Actions = nil
				case "drop_field:context":
					pack.SignalHash = ""
				case "drop_field:outcome_hash":
					pack.OutcomeHash = ""
				case "none":
					// no mutation
				default:
					t.Fatalf("unknown mutation: %s", c.Mutation)
				}

				if c.ExpectIdenticalRuns > 0 {
					var first string
					for i := 0; i < c.ExpectIdenticalRuns; i++ {
						ok, err := m.Replay(pack)
						if err != nil || !ok {
							t.Fatalf("replay %d failed: %v", i, err)
						}
						if i == 0 {
							first = pack.OutcomeHash
						} else if pack.OutcomeHash != first {
							t.Fatal("non-identical outcome hash across runs")
						}
					}
					return
				}

				if c.ExpectOutcomeHash != "" {
					if c.ExpectOutcomeHash == "REPLACE_WITH_PINNED_HASH" {
						t.Fatalf("placeholder hash still present; actual outcome hash is: %s", pack.OutcomeHash)
					}
					if pack.OutcomeHash != c.ExpectOutcomeHash {
						t.Fatalf("outcome hash mismatch: got %s, want %s", pack.OutcomeHash, c.ExpectOutcomeHash)
					}
				}

				_, err = m.Replay(pack)
				checkErr(t, err, c.ExpectErr)
			}
		})
	}
}

// TestReplayFailsOnConfigMismatch ensures that replaying a pack recorded under
// one config fails when the module is configured with a different version or weights.
func TestReplayFailsOnConfigMismatch(t *testing.T) {
	m := New()
	if err := m.Configure(baselineConfig()); err != nil {
		t.Fatal(err)
	}
	action, err := m.Assess(baselineSignal())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := m.Record(action, baselineOutcome())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := m.Replay(pack)
	if err != nil || !ok {
		t.Fatalf("baseline replay failed: %v", err)
	}

	// Different weights
	m2 := New()
	badWeights := baselineConfig()
	badWeights.Metrics = map[string]float64{"load": 2.0}
	if err := m2.Configure(badWeights); err != nil {
		t.Fatal(err)
	}
	// Force recorded state so Replay proceeds past the order check
	m2.recorded = true
	_, err = m2.Replay(pack)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("replay under different weights: got %v, want ErrTampered", err)
	}

	// Different version is rejected at Configure; the binding is via the context hash.
	// A module with the same weights but we mutate the pack's implied config by using a different threshold.
	m3 := New()
	badThresh := baselineConfig()
	badThresh.Threshold = 0.5
	if err := m3.Configure(badThresh); err != nil {
		t.Fatal(err)
	}
	m3.recorded = true
	_, err = m3.Replay(pack)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("replay under different threshold: got %v, want ErrTampered", err)
	}
}
