package main

import (
	"fmt"
	"html"
	"math"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// algorithmInfo maps a benchmark's raw identifier (as parsed by parse.go)
// to its display name, benchmark suite, and a fixed categorical color slot.
// Slot assignment is deliberately consistent across suites: slot 1
// (blue) always means "classical", slot 2 (aqua) always means
// "post-quantum", so color keeps the same meaning throughout the
// dashboard, not just within one chart.
type algorithmInfo struct {
	id      string
	display string
	suite   string
	slot    int
}

const (
	suiteKEM       = "KEM"
	suiteSignature = "Signature"
)

// algorithms is the fixed, known set of algorithms benchmarked anywhere in
// this repo (see internal/kem/*/*_bench_test.go and
// internal/sig/*/*_bench_test.go). Order within a suite is display order
// for the legend and table.
var algorithms = []algorithmInfo{
	{id: "X25519", display: "X25519", suite: suiteKEM, slot: 1},
	{id: "MLKEM768", display: "ML-KEM-768", suite: suiteKEM, slot: 2},
	{id: "Hybrid", display: "Hybrid(X25519+ML-KEM-768)", suite: suiteKEM, slot: 3},
	{id: "Ed25519", display: "Ed25519", suite: suiteSignature, slot: 1},
	{id: "MLDSA65", display: "ML-DSA-65", suite: suiteSignature, slot: 2},
}

// suiteOperations lists each suite's operations in fixed display order.
var suiteOperations = map[string][]string{
	suiteKEM:       {"GenerateKeyPair", "Encapsulate", "Decapsulate"},
	suiteSignature: {"GenerateKeyPair", "Sign", "Verify"},
}

// operationLabels renders an operation identifier for display.
var operationLabels = map[string]string{
	"GenerateKeyPair": "Generate Keypair",
	"Encapsulate":     "Encapsulate",
	"Decapsulate":     "Decapsulate",
	"Sign":            "Sign",
	"Verify":          "Verify",
}

// metricSpec is one of the three metrics `go test -benchmem` reports,
// charted separately (one axis per chart, never a dual-axis chart mixing
// time and memory).
type metricSpec struct {
	label   string
	unit    string
	extract func(benchResult) float64
}

var metrics = []metricSpec{
	{label: "Time per operation", unit: "ns/op", extract: func(r benchResult) float64 { return r.nsPerOp }},
	{label: "Memory per operation", unit: "B/op", extract: func(r benchResult) float64 { return float64(r.bytesPerOp) }},
	{label: "Allocations per operation", unit: "allocs/op", extract: func(r benchResult) float64 { return float64(r.allocsPerOp) }},
}

// renderDashboard renders the full HTML dashboard for the given benchmark
// results.
func renderDashboard(results []benchResult) (string, error) {
	byAlgo := map[string][]benchResult{}
	for _, r := range results {
		byAlgo[r.algorithm] = append(byAlgo[r.algorithm], r)
	}

	var b strings.Builder
	b.WriteString(dashboardHead())

	b.WriteString(`<div class="viz-root">` + "\n")
	b.WriteString(`<header><h1>pq-migration-lab benchmark dashboard</h1>` +
		`<p class="meta">Generated ` + time.Now().UTC().Format("2006-01-02 15:04 MST") +
		` on ` + html.EscapeString(runtime.GOOS+"/"+runtime.GOARCH) + `, ` + html.EscapeString(runtime.Version()) +
		`. Not absolute performance claims. Results vary by hardware. ` +
		`Reproduce with <code>go run ./cmd/benchdash</code> (or inside Docker: ` +
		`<code>docker run --rm pq-migration-lab go run ./cmd/benchdash</code>).</p></header>` + "\n")

	for _, suite := range []string{suiteKEM, suiteSignature} {
		var suiteAlgos []algorithmInfo
		for _, a := range algorithms {
			if a.suite == suite {
				suiteAlgos = append(suiteAlgos, a)
			}
		}
		section, err := renderSuiteSection(suite, suiteAlgos, byAlgo)
		if err != nil {
			return "", err
		}
		b.WriteString(section)
	}

	b.WriteString(`</div>` + "\n")
	b.WriteString(dashboardTail())
	return b.String(), nil
}

func renderSuiteSection(suite string, suiteAlgos []algorithmInfo, byAlgo map[string][]benchResult) (string, error) {
	operations := suiteOperations[suite]

	var b strings.Builder
	fmt.Fprintf(&b, "<section>\n<h2>%s benchmarks</h2>\n", html.EscapeString(suite))
	b.WriteString(renderLegend(suiteAlgos))

	b.WriteString(`<div class="chart-row">` + "\n")
	for _, m := range metrics {
		chart, err := renderBarChart(suite, operations, suiteAlgos, byAlgo, m)
		if err != nil {
			return "", err
		}
		b.WriteString(chart)
	}
	b.WriteString(`</div>` + "\n")

	b.WriteString(renderTable(suite, operations, suiteAlgos, byAlgo))
	b.WriteString("</section>\n")
	return b.String(), nil
}

func renderLegend(suiteAlgos []algorithmInfo) string {
	var b strings.Builder
	b.WriteString(`<ul class="legend">` + "\n")
	for _, a := range suiteAlgos {
		fmt.Fprintf(&b, `<li><span class="swatch" style="background:var(--series-%d)"></span>%s</li>`+"\n",
			a.slot, html.EscapeString(a.display))
	}
	b.WriteString(`</ul>` + "\n")
	return b.String()
}

const (
	chartW       = 640.0
	chartH       = 320.0
	marginLeft   = 70.0
	marginRight  = 20.0
	marginTop    = 32.0
	marginBottom = 56.0
	barGap       = 2.0
	maxBarWidth  = 24.0
	groupPadFrac = 0.28
	barRadius    = 4.0
)

// renderBarChart renders one grouped-bar-chart SVG: one group per
// operation, one bar per algorithm within the group, colored by the
// algorithm's fixed categorical slot.
func renderBarChart(suite string, operations []string, suiteAlgos []algorithmInfo, byAlgo map[string][]benchResult, m metricSpec) (string, error) {
	// value[operation][algorithm id] = metric value
	value := map[string]map[string]float64{}
	maxVal := 0.0
	for _, a := range suiteAlgos {
		for _, r := range byAlgo[a.id] {
			v := m.extract(r)
			if value[r.operation] == nil {
				value[r.operation] = map[string]float64{}
			}
			value[r.operation][a.id] = v
			if v > maxVal {
				maxVal = v
			}
		}
	}

	step := niceStep(maxVal)
	top := step * math.Ceil(maxVal/step)
	if top <= 0 {
		top = 1
	}
	numTicks := int(math.Round(top/step)) + 1

	plotW := chartW - marginLeft - marginRight
	plotH := chartH - marginTop - marginBottom
	groupW := plotW / float64(len(operations))

	n := len(suiteAlgos)
	barW := ((groupW * (1 - groupPadFrac)) - barGap*float64(n-1)) / float64(n)
	if barW > maxBarWidth {
		barW = maxBarWidth
	}
	groupContentW := barW*float64(n) + barGap*float64(n-1)

	var b strings.Builder
	fmt.Fprintf(&b, `<figure class="chart">`+"\n")
	fmt.Fprintf(&b, `<figcaption><strong>%s</strong>: %s (%s)<span class="muted">, lower is better</span></figcaption>`+"\n",
		html.EscapeString(suite), html.EscapeString(m.label), html.EscapeString(m.unit))
	fmt.Fprintf(&b, `<svg viewBox="0 0 %g %g" role="img" aria-label="%s %s by operation">`+"\n",
		chartW, chartH, html.EscapeString(suite), html.EscapeString(m.label))

	// Gridlines + y-axis tick labels.
	for i := 0; i < numTicks; i++ {
		tick := float64(i) * step
		y := marginTop + plotH - (tick/top)*plotH
		fmt.Fprintf(&b, `<line class="gridline" x1="%g" y1="%g" x2="%g" y2="%g"/>`+"\n",
			marginLeft, y, marginLeft+plotW, y)
		fmt.Fprintf(&b, `<text class="tick" x="%g" y="%g" text-anchor="end">%s</text>`+"\n",
			marginLeft-8, y+4, formatCommaFloat(tick))
	}

	// Bars, grouped by operation.
	for gi, op := range operations {
		groupX := marginLeft + groupW*float64(gi)
		groupCenter := groupX + groupW/2
		startX := groupCenter - groupContentW/2

		for ai, a := range suiteAlgos {
			v := value[op][a.id]
			barH := 0.0
			if top > 0 {
				barH = (v / top) * plotH
			}
			x := startX + float64(ai)*(barW+barGap)
			y := marginTop + plotH - barH

			tip := fmt.Sprintf("%s, %s: %s %s", a.display, operationLabels[op], formatCommaFloat(v), m.unit)
			fmt.Fprintf(&b, `<g tabindex="0" data-tip="%s">`+"\n", html.EscapeString(tip))
			fmt.Fprintf(&b, `<path class="bar" fill="var(--series-%d)" d="%s"/>`+"\n",
				a.slot, roundedTopBarPath(x, y, barW, barH, barRadius))
			fmt.Fprintf(&b, `<text class="bar-label" x="%g" y="%g" text-anchor="middle">%s</text>`+"\n",
				x+barW/2, y-6, formatCommaFloat(v))
			b.WriteString("</g>\n")
		}

		fmt.Fprintf(&b, `<text class="axis-label" x="%g" y="%g" text-anchor="middle">%s</text>`+"\n",
			groupCenter, marginTop+plotH+20, html.EscapeString(operationLabels[op]))
	}

	fmt.Fprintf(&b, `<line class="baseline" x1="%g" y1="%g" x2="%g" y2="%g"/>`+"\n",
		marginLeft, marginTop+plotH, marginLeft+plotW, marginTop+plotH)

	b.WriteString("</svg>\n</figure>\n")
	return b.String(), nil
}

// roundedTopBarPath returns an SVG path for a bar with rounded top corners
// and a square bottom (anchored to the baseline), per the dataviz skill's
// mark spec. height may be 0 (a zero-value bar still renders as a flat
// line at the baseline).
func roundedTopBarPath(x, y, width, height, radius float64) string {
	r := radius
	if r > width/2 {
		r = width / 2
	}
	if r > height {
		r = height
	}
	if r < 0 {
		r = 0
	}
	bottom := y + height
	return fmt.Sprintf(
		"M %g %g Q %g %g %g %g L %g %g Q %g %g %g %g L %g %g L %g %g Z",
		x, y+r, // start, left side just below the curve
		x, y, x+r, y, // curve up to top-left corner
		x+width-r, y, // across the top
		x+width, y, x+width, y+r, // curve down to top-right corner
		x+width, bottom, // down the right side
		x, bottom, // across the bottom (square)
	)
}

func renderTable(suite string, operations []string, suiteAlgos []algorithmInfo, byAlgo map[string][]benchResult) string {
	byOpAlgo := map[string]map[string]benchResult{}
	for _, a := range suiteAlgos {
		for _, r := range byAlgo[a.id] {
			if byOpAlgo[r.operation] == nil {
				byOpAlgo[r.operation] = map[string]benchResult{}
			}
			byOpAlgo[r.operation][a.id] = r
		}
	}

	var b strings.Builder
	b.WriteString(`<details class="data-table"><summary>Table view</summary>` + "\n")
	b.WriteString("<table>\n<thead><tr><th>Algorithm</th><th>Operation</th><th>ns/op</th><th>B/op</th><th>allocs/op</th></tr></thead>\n<tbody>\n")
	for _, op := range operations {
		for _, a := range suiteAlgos {
			r, ok := byOpAlgo[op][a.id]
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(a.display), html.EscapeString(operationLabels[op]),
				formatCommaFloat(r.nsPerOp), formatCommaFloat(float64(r.bytesPerOp)), formatCommaFloat(float64(r.allocsPerOp)))
		}
	}
	b.WriteString("</tbody>\n</table>\n</details>\n")
	return b.String()
}

// niceStep picks a "clean" gridline step (1/2/5 × a power of ten) for an
// axis topping out around maxVal, aiming for roughly 4 gridlines.
func niceStep(maxVal float64) float64 {
	if maxVal <= 0 {
		return 1
	}
	magnitude := math.Pow(10, math.Floor(math.Log10(maxVal)))
	residual := maxVal / magnitude
	var niceResidual float64
	switch {
	case residual <= 1:
		niceResidual = 1
	case residual <= 2:
		niceResidual = 2
	case residual <= 5:
		niceResidual = 5
	default:
		niceResidual = 10
	}
	step := niceResidual * magnitude / 4
	if step <= 0 {
		step = 1
	}
	return step
}

// formatCommaFloat formats v with thousands separators and no decimal
// places: every metric here (ns/op, B/op, allocs/op) is effectively
// integer-valued at the precision `go test -benchmem` reports.
func formatCommaFloat(v float64) string {
	return formatCommaInt(int64(math.Round(v)))
}

func formatCommaInt(v int64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	s := strconv.FormatInt(v, 10)
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	out := strings.Join(parts, ",")
	if neg {
		out = "-" + out
	}
	return out
}

// dashboardHead and dashboardTail bracket the per-suite sections with the
// page shell: palette custom properties (light + dark, per the dataviz
// skill's reference palette), chart chrome, and the shared tooltip
// wiring. Kept as plain string constants rather than html/template since
// every dynamic value inserted into the body elsewhere is either a
// compile-time-fixed identifier (algorithm/operation names, from the
// fixed maps above) or a number formatted by this package: nothing here
// crosses a trust boundary the way user-supplied HTML would.
func dashboardHead() string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pq-migration-lab benchmark dashboard</title>
<style>
  .viz-root {
    --surface-1: #fcfcfb;
    --page: #f9f9f7;
    --text-primary: #0b0b0b;
    --text-secondary: #52514e;
    --text-muted: #898781;
    --gridline: #e1e0d9;
    --baseline: #c3c2b7;
    /* dataviz reference palette, categorical slots 1-3: blue = classical,
       aqua = post-quantum, yellow = hybrid (see algorithmInfo.slot above) */
    --series-1: #2a78d6;
    --series-2: #1baf7a;
    --series-3: #eda100;
  }
  @media (prefers-color-scheme: dark) {
    .viz-root {
      --surface-1: #1a1a19;
      --page: #0d0d0d;
      --text-primary: #ffffff;
      --text-secondary: #c3c2b7;
      --text-muted: #898781;
      --gridline: #2c2c2a;
      --baseline: #383835;
      --series-1: #3987e5;
      --series-2: #199e70;
      --series-3: #c98500;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--page);
    color: var(--text-primary);
    overflow-wrap: break-word;
  }
  .viz-root { padding: 24px clamp(16px, 4vw, 48px) 64px; max-width: 1200px; margin: 0 auto; }
  header p.meta { color: var(--text-secondary); max-width: 72ch; }
  code { background: var(--surface-1); border-radius: 3px; padding: 0 4px; }
  h1 { font-size: 1.5rem; margin-bottom: 4px; }
  h2 { font-size: 1.15rem; border-bottom: 1px solid var(--gridline); padding-bottom: 8px; }
  section { margin-top: 40px; }
  .legend { list-style: none; display: flex; flex-wrap: wrap; gap: 16px; padding: 0; margin: 0 0 16px; color: var(--text-secondary); font-size: 0.9rem; }
  .legend li { display: flex; align-items: center; gap: 6px; }
  .swatch { width: 12px; height: 12px; border-radius: 2px; display: inline-block; }
  .chart-row { display: flex; flex-wrap: wrap; gap: 24px; }
  figure.chart { background: var(--surface-1); border-radius: 8px; padding: 12px 16px 4px; margin: 0; flex: 1 1 320px; max-width: 480px; min-width: 0; }
  figcaption { font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 4px; }
  figcaption .muted { color: var(--text-muted); }
  svg { width: 100%; height: auto; display: block; }
  .gridline { stroke: var(--gridline); stroke-width: 1; }
  .baseline { stroke: var(--baseline); stroke-width: 1; }
  .tick, .axis-label { fill: var(--text-muted); font-size: 10px; }
  .bar-label { fill: var(--text-secondary); font-size: 10px; }
  .bar { cursor: pointer; }
  g[data-tip]:hover .bar, g[data-tip]:focus .bar { opacity: 0.85; outline: none; }
  g[data-tip]:focus { outline: 2px solid var(--text-muted); outline-offset: 2px; }
  details.data-table { margin-top: 16px; color: var(--text-secondary); }
  details.data-table summary { cursor: pointer; color: var(--text-primary); font-weight: 600; }
  table { border-collapse: collapse; margin-top: 8px; width: 100%; font-size: 0.9rem; }
  th, td { text-align: left; padding: 4px 12px 4px 0; border-bottom: 1px solid var(--gridline); font-variant-numeric: tabular-nums; }
  th { color: var(--text-muted); font-weight: 600; }
  #benchdash-tooltip {
    position: fixed; pointer-events: none; z-index: 10;
    background: var(--text-primary); color: var(--surface-1);
    font-size: 0.8rem; padding: 4px 8px; border-radius: 4px;
    transform: translate(-50%, -100%); margin-top: -8px;
    opacity: 0; transition: opacity 0.1s ease;
    max-width: 260px;
  }
  #benchdash-tooltip.visible { opacity: 1; }
</style>
</head>
<body>
<div id="benchdash-tooltip" role="tooltip"></div>
`
}

func dashboardTail() string {
	return `<script>
(function () {
  var tip = document.getElementById('benchdash-tooltip');
  function show(el) {
    var text = el.getAttribute('data-tip');
    if (!text) return;
    tip.textContent = text;
    var rect = el.getBoundingClientRect();
    tip.style.left = (rect.left + rect.width / 2) + 'px';
    tip.style.top = rect.top + 'px';
    tip.classList.add('visible');
  }
  function hide() {
    tip.classList.remove('visible');
  }
  document.addEventListener('pointerover', function (e) {
    var el = e.target.closest('[data-tip]');
    if (el) show(el);
  });
  document.addEventListener('pointerout', function (e) {
    var el = e.target.closest('[data-tip]');
    if (el) hide();
  });
  document.addEventListener('focusin', function (e) {
    var el = e.target.closest('[data-tip]');
    if (el) show(el);
  });
  document.addEventListener('focusout', function (e) {
    var el = e.target.closest('[data-tip]');
    if (el) hide();
  });
})();
</script>
</body>
</html>
`
}
