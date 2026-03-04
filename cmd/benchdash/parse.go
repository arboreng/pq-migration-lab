// Command benchdash runs this module's KEM and signature benchmarks and
// renders their results as a static HTML dashboard (benchmarks/dashboard.html
// by default), replacing hand-transcribed markdown tables with generated,
// visual output. See docs/architecture.md's Performance section.
package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// benchResult is one parsed `go test -bench=. -benchmem` result line.
type benchResult struct {
	algorithm   string // raw identifier, e.g. "MLKEM768" (see algorithms in render.go)
	operation   string // e.g. "Encapsulate"
	nsPerOp     float64
	bytesPerOp  uint64
	allocsPerOp uint64
}

// benchNameRE matches this module's BenchmarkXxx function names, e.g.
// "BenchmarkMLKEM768Encapsulate-4". The operation alternatives are the
// fixed, known set of operations benchmarked anywhere in this repo (see
// internal/kem/*/*_bench_test.go and internal/sig/*/*_bench_test.go); a
// benchmark using a different operation name simply won't be recognized
// and is skipped, same as any other non-benchmark line.
var benchNameRE = regexp.MustCompile(`^Benchmark([A-Za-z0-9]+?)(GenerateKeyPair|Encapsulate|Decapsulate|Sign|Verify)-\d+$`)

// parseBenchLine parses one line of `go test -bench=. -benchmem` output,
// e.g.:
//
//	BenchmarkMLKEM768Encapsulate-4    14072    85349 ns/op    496 B/op    9 allocs/op
//
// It returns ok=false for any line that isn't a recognized benchmark result
// (headers, PASS/ok summary lines, blank lines, etc.), rather than erroring:
// most lines in `go test` output aren't benchmark results at all.
func parseBenchLine(line string) (r benchResult, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return benchResult{}, false
	}
	m := benchNameRE.FindStringSubmatch(fields[0])
	if m == nil {
		return benchResult{}, false
	}
	r.algorithm, r.operation = m[1], m[2]

	// fields[1] is the iteration count (unused here); the rest are
	// (value, unit) pairs, order-independent.
	for i := 2; i+1 < len(fields); i += 2 {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			continue
		}
		switch fields[i+1] {
		case "ns/op":
			r.nsPerOp = value
		case "B/op":
			r.bytesPerOp = uint64(value)
		case "allocs/op":
			r.allocsPerOp = uint64(value)
		}
	}
	return r, true
}

// parseBenchOutput parses every recognized benchmark line from r, in the
// order encountered.
func parseBenchOutput(r io.Reader) ([]benchResult, error) {
	var results []benchResult
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if res, ok := parseBenchLine(scanner.Text()); ok {
			results = append(results, res)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan benchmark output: %w", err)
	}
	return results, nil
}
