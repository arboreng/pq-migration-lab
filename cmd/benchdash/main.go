package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	out := flag.String("out", "benchmarks/dashboard.html", "output HTML path")
	flag.Parse()

	pkgs := flag.Args()
	if len(pkgs) == 0 {
		pkgs = []string{"./internal/kem/...", "./internal/sig/..."}
	}

	results, err := runBenchmarks(pkgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "error: no benchmark results parsed from %v\n", pkgs)
		os.Exit(1)
	}

	html, err := renderDashboard(results)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(html), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("benchdash: wrote %d benchmark results to %s\n", len(results), *out)
}

// runBenchmarks runs `go test -bench=. -benchmem` against pkgs and parses
// its output. -run=^$ skips every non-benchmark test in pkgs, so only
// benchmark timing is exercised.
func runBenchmarks(pkgs []string) ([]benchResult, error) {
	args := append([]string{"test", "-run=^$", "-bench=.", "-benchmem"}, pkgs...)
	cmd := exec.Command("go", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %v: %w\n%s", args, err, stderr.String())
	}
	return parseBenchOutput(&stdout)
}
