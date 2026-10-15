package voleith

import (
	"os"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"
)

func benchInputs(b testing.TB) (Statement, []byte, []byte) {
	f := loadKAT(b)
	v := f.Vectors[0]
	return Statement{StatementHMAC, unhex(b, v.PublicInputs)}, unhex(b, v.Message), unhex(b, v.Proof)
}

// BenchmarkVerify reports the mean; run with -cpu 1 for one thread.
func BenchmarkVerify(b *testing.B) {
	st, m, p := benchInputs(b)
	statement1Circuit()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(st, m, p) {
			b.Fatal("rejected")
		}
	}
}

// TestMedianVerifyTime measures the median single-thread verify time of a
// valid KAT proof, of the same proof with chall3 = ff…ff (rejected after a
// full verification), and of a valid 65,535-byte-message proof from the
// differential set. Enabled with VOLEITH_BENCH=<runs>.
func TestMedianVerifyTime(t *testing.T) {
	runsEnv := os.Getenv("VOLEITH_BENCH")
	if runsEnv == "" {
		t.Skip("set VOLEITH_BENCH=<runs> to measure")
	}
	runs, err := strconv.Atoi(runsEnv)
	if err != nil || runs < 1 {
		t.Fatalf("VOLEITH_BENCH=%q", runsEnv)
	}
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)

	st, m, p := benchInputs(t)
	statement1Circuit() // built once per process, outside the timing
	ones := append([]byte(nil), p...)
	for i := statement1Layout.offH; i < len(ones); i++ {
		ones[i] = 0xff
	}
	measure := func(name string, want bool, st Statement, m, p []byte) {
		for i := 0; i < 3; i++ { // warm-up
			Verify(st, m, p)
		}
		d := make([]time.Duration, runs)
		for i := range d {
			start := time.Now()
			got := Verify(st, m, p)
			d[i] = time.Since(start)
			if got != want {
				t.Fatalf("%s: verdict %v", name, got)
			}
		}
		slices.Sort(d)
		t.Logf("%-34s runs=%d median=%.2f ms min=%.2f ms max=%.2f ms", name, runs,
			ms(d[runs/2]), ms(d[0]), ms(d[runs-1]))
	}
	measure("valid KAT 0 (96-byte message)", true, st, m, p)
	measure("KAT 0 with chall3 = ff..ff", false, st, m, ones)
	if lst, lm, lp, ok := longMessageCase(t); ok {
		measure("valid, 65,535-byte message", true, lst, lm, lp)
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
