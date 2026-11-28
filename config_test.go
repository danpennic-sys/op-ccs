package ccs

import (
	"errors"
	"math"
	"sync"
	"testing"
)

// runAssess returns the raw weighted score, the pass/fail outcome, and any error.
func runAssess(m *RealModule, metrics map[string]float64) (score float64, pass bool, err error) {
	return m.score(metrics)
}

func goodConfig() Config {
	return Config{
		Version:   ConfigV1,
		Threshold: 0.8,
		Metrics:   map[string]float64{"load": 1.0},
	}
}

func mustConfigure(t *testing.T, m *RealModule, c Config) {
	t.Helper()
	if err := m.Configure(c); err != nil {
		t.Fatalf("Configure(%+v) unexpectedly failed: %v", c, err)
	}
}

func TestAssessBeforeConfigureFailsClosed(t *testing.T) {
	m := New()
	_, _, err := runAssess(m, map[string]float64{"load": 0.3})
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("Assess before Configure: got %v, want ErrMissingConfig", err)
	}
}

func TestConfigureRejections(t *testing.T) {
	nan, pinf, ninf := math.NaN(), math.Inf(1), math.Inf(-1)
	negZero := math.Copysign(0, -1)

	cases := []struct {
		name string
		mut  func(*Config)
		want error
	}{
		{"empty version", func(c *Config) { c.Version = "" }, ErrMissingConfig},
		{"unknown version", func(c *Config) { c.Version = "op-ccs-config/v2" }, ErrUnsupportedVersion},
		{"threshold zero", func(c *Config) { c.Threshold = 0 }, ErrMissingConfig},
		{"threshold negative zero", func(c *Config) { c.Threshold = negZero }, ErrMissingConfig},
		{"threshold negative", func(c *Config) { c.Threshold = -0.1 }, ErrMissingConfig},
		{"threshold NaN", func(c *Config) { c.Threshold = nan }, ErrMalformedInput},
		{"threshold +Inf", func(c *Config) { c.Threshold = pinf }, ErrMalformedInput},
		{"threshold -Inf", func(c *Config) { c.Threshold = ninf }, ErrMalformedInput},
		{"weight NaN", func(c *Config) { c.Metrics = map[string]float64{"load": nan} }, ErrMalformedInput},
		{"weight +Inf", func(c *Config) { c.Metrics = map[string]float64{"load": pinf} }, ErrMalformedInput},
		{"weight negative", func(c *Config) { c.Metrics = map[string]float64{"load": -1} }, ErrMalformedInput},
		{"empty metric key", func(c *Config) { c.Metrics = map[string]float64{"": 1} }, ErrMalformedInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			c := goodConfig()
			tc.mut(&c)
			err := m.Configure(c)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if _, _, aerr := runAssess(m, map[string]float64{"load": 0.3}); !errors.Is(aerr, ErrMissingConfig) {
				t.Fatalf("module ran after rejected Configure: %v", aerr)
			}
		})
	}
}

func TestFailedConfigurePreservesPriorConfig(t *testing.T) {
	m := New()
	mustConfigure(t, m, goodConfig())
	sig := map[string]float64{"load": 0.9}
	s0, p0, err := runAssess(m, sig)
	if err != nil {
		t.Fatal(err)
	}

	bad := goodConfig()
	bad.Threshold = math.NaN()
	if err := m.Configure(bad); !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("got %v, want ErrMalformedInput", err)
	}

	s1, p1, err := runAssess(m, sig)
	if err != nil {
		t.Fatalf("Assess after failed Configure: %v", err)
	}
	if math.Float64bits(s0) != math.Float64bits(s1) || p0 != p1 {
		t.Fatalf("state changed after failed Configure: (%v,%v) -> (%v,%v)", s0, p0, s1, p1)
	}
}

func TestThresholdBoundary(t *testing.T) {
	m := New()
	mustConfigure(t, m, Config{Version: ConfigV1, Threshold: 0.5,
		Metrics: map[string]float64{"load": 1.0}})

	if _, pass, err := runAssess(m, map[string]float64{"load": 0.5}); err != nil || !pass {
		t.Fatalf("score == threshold: pass=%v err=%v, want pass=true", pass, err)
	}
	below := math.Nextafter(0.5, 0)
	if _, pass, err := runAssess(m, map[string]float64{"load": below}); err != nil || pass {
		t.Fatalf("score just below threshold: pass=%v err=%v, want pass=false", pass, err)
	}
}

func TestConfigureDoesNotAliasCallerMap(t *testing.T) {
	m := New()
	w := map[string]float64{"load": 1.0}
	mustConfigure(t, m, Config{Version: ConfigV1, Threshold: 0.8, Metrics: w})
	sig := map[string]float64{"load": 0.5}
	s0, _, err := runAssess(m, sig)
	if err != nil {
		t.Fatal(err)
	}

	w["load"] = 100
	w["extra"] = 5
	delete(w, "load")

	s1, _, err := runAssess(m, sig)
	if err != nil {
		t.Fatal(err)
	}
	if math.Float64bits(s0) != math.Float64bits(s1) {
		t.Fatalf("score changed after caller mutated map: %v -> %v", s0, s1)
	}
}

func TestScoreIsOrderDeterministic(t *testing.T) {
	m := New()
	mustConfigure(t, m, Config{Version: ConfigV1, Threshold: 1e-300,
		Metrics: map[string]float64{"a": 1, "b": 1, "c": 1}})
	sig := map[string]float64{"a": 1e17, "b": 1, "c": -1e17}

	first, _, err := runAssess(m, sig)
	if err != nil {
		t.Fatal(err)
	}
	if first != 0 {
		t.Fatalf("sorted-key sum = %v, want 0 (a+b rounds to a, then -c)", first)
	}
	want := math.Float64bits(first)
	for i := 0; i < 1000; i++ {
		got, _, err := runAssess(m, sig)
		if err != nil {
			t.Fatal(err)
		}
		if math.Float64bits(got) != want {
			t.Fatalf("run %d: bits %x != %x", i, math.Float64bits(got), want)
		}
	}
}

func TestAssessRejectsNonFiniteSignal(t *testing.T) {
	m := New()
	mustConfigure(t, m, goodConfig())
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, _, err := runAssess(m, map[string]float64{"load": v}); !errors.Is(err, ErrMalformedInput) {
			t.Fatalf("signal %v: got %v, want ErrMalformedInput", v, err)
		}
	}
}

// Concurrent Configure/Assess must be race-free and every Assess must see a
// complete snapshot (old or new), never a mix. Configs differ in both
// weights and threshold so a torn read is detectable.
func TestConcurrentConfigureAssess(t *testing.T) {
	m := New()
	mustConfigure(t, m, Config{Version: ConfigV1, Threshold: 0.5,
		Metrics: map[string]float64{"load": 1.0}})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 64)

	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Snapshot A: weight 1, threshold 0.5 → score 0.4 < 0.5 → fail
				// Snapshot B: weight 2, threshold 0.7 → score 0.8 >= 0.7 → pass
				s, p, err := runAssess(m, map[string]float64{"load": 0.4})
				if err != nil {
					errs <- err
					return
				}
				if (s == 0.4 && !p) || (s == 0.8 && p) {
					continue
				}
				errs <- errors.New("torn snapshot: score/pass is neither config A nor B")
				return
			}
		}()
	}

	for i := 0; i < 2000; i++ {
		if i%2 == 0 {
			mustConfigure(t, m, Config{Version: ConfigV1, Threshold: 0.5,
				Metrics: map[string]float64{"load": 1.0}})
		} else {
			mustConfigure(t, m, Config{Version: ConfigV1, Threshold: 0.7,
				Metrics: map[string]float64{"load": 2.0}})
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
