// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Operator Pages LLC
// Date: 2026-11-22

package ccs

import (
	"encoding/json"
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

func TestVectors(t *testing.T) {
	cases := loadCases(t)

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			m := NewStub()
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
				if c.ExpectErr != nil {
					if lastErr == nil || !strings.Contains(lastErr.Error(), strings.TrimPrefix(*c.ExpectErr, "Err")) {
						t.Fatalf("expected error containing %q, got %v", *c.ExpectErr, lastErr)
					}
				}
				return

			default:
				// Normal Assess -> Record path, then mutate, then Replay
				action, err := m.Assess(signal)
				if err != nil {
					t.Fatal(err)
				}
				pack, err := m.Record(action, outcome)
				if err != nil {
					t.Fatal(err)
				}

				// Apply mutation
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

				if c.ExpectOutcomeHash != "" && c.ExpectOutcomeHash != "REPLACE_WITH_PINNED_HASH" {
					if pack.OutcomeHash != c.ExpectOutcomeHash {
						t.Fatalf("outcome hash mismatch: got %s, want %s", pack.OutcomeHash, c.ExpectOutcomeHash)
					}
				}

				_, err = m.Replay(pack)
				if c.ExpectErr == nil {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
				} else {
					want := *c.ExpectErr
					if err == nil {
						t.Fatalf("expected %s, got nil", want)
					}
					// Match by error string fragment or name
					if !strings.Contains(err.Error(), strings.TrimPrefix(want, "Err")) && err.Error() != want {
						t.Fatalf("expected error %q, got %v", want, err)
					}
				}
			}
		})
	}
}
