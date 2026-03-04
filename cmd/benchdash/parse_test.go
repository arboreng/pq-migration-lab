package main

import (
	"strings"
	"testing"
)

func TestParseBenchLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want benchResult
	}{
		{
			name: "kem operation",
			line: "BenchmarkMLKEM768Encapsulate-4    14072    85349 ns/op    496 B/op    9 allocs/op",
			want: benchResult{algorithm: "MLKEM768", operation: "Encapsulate", nsPerOp: 85349, bytesPerOp: 496, allocsPerOp: 9},
		},
		{
			name: "signature operation, zero allocs",
			line: "BenchmarkEd25519Verify-8    21824    54963 ns/op    0 B/op    0 allocs/op",
			want: benchResult{algorithm: "Ed25519", operation: "Verify", nsPerOp: 54963, bytesPerOp: 0, allocsPerOp: 0},
		},
		{
			name: "multi-digit GOMAXPROCS suffix",
			line: "BenchmarkX25519GenerateKeyPair-128    29676    40591 ns/op    368 B/op    6 allocs/op",
			want: benchResult{algorithm: "X25519", operation: "GenerateKeyPair", nsPerOp: 40591, bytesPerOp: 368, allocsPerOp: 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseBenchLine(tt.line)
			if !ok {
				t.Fatalf("parseBenchLine(%q): ok = false, want true", tt.line)
			}
			if got != tt.want {
				t.Errorf("parseBenchLine(%q) = %+v, want %+v", tt.line, got, tt.want)
			}
		})
	}
}

func TestParseBenchLineRejectsNonBenchmarkLines(t *testing.T) {
	lines := []string{
		"",
		"goos: linux",
		"goarch: arm64",
		"pkg: github.com/arboreng/pq-migration-lab/internal/kem/pq",
		"PASS",
		"ok  \tgithub.com/arboreng/pq-migration-lab/internal/kem/pq\t3.456s",
		"BenchmarkUnknownOperation-4    100    1000 ns/op",
	}
	for _, line := range lines {
		if _, ok := parseBenchLine(line); ok {
			t.Errorf("parseBenchLine(%q): ok = true, want false", line)
		}
	}
}

func TestParseBenchOutput(t *testing.T) {
	output := `goos: linux
goarch: arm64
pkg: github.com/arboreng/pq-migration-lab/internal/kem/classical
BenchmarkX25519GenerateKeyPair-4    29676    40591 ns/op    368 B/op    6 allocs/op
BenchmarkX25519Encapsulate-4    14072    85349 ns/op    496 B/op    9 allocs/op
PASS
ok  	github.com/arboreng/pq-migration-lab/internal/kem/classical	3.456s
`
	results, err := parseBenchOutput(strings.NewReader(output))
	if err != nil {
		t.Fatalf("parseBenchOutput: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("parseBenchOutput: got %d results, want 2: %+v", len(results), results)
	}
	if results[0].operation != "GenerateKeyPair" || results[1].operation != "Encapsulate" {
		t.Errorf("parseBenchOutput: unexpected operations: %+v", results)
	}
}
