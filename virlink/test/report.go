// report.go — structured output (terminal table + JSON).
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

// ── data model ────────────────────────────────────────────────────────────────

type Direction string

const (
	DirAB Direction = "A→B" // A=server, B=client
	DirBA Direction = "B→A" // B=server, A=client
)

// ProtoResult holds all measurements for one (protocol, direction) pair.
type ProtoResult struct {
	Protocol  string    `json:"protocol"`
	Label     string    `json:"label"`
	Direction Direction `json:"direction"`
	Status    string    `json:"status"` // pass | fail | skip | error

	// throughput (from /bench)
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`

	// latency (from ping)
	LatencyP50Ms float64 `json:"latency_p50_ms"`
	LatencyP95Ms float64 `json:"latency_p95_ms"`
	LatencyP99Ms float64 `json:"latency_p99_ms"`
	LossPct      float64 `json:"loss_pct"`

	// resource usage
	ServerCPUPct    float64 `json:"server_cpu_pct"`
	ServerMemMiB    float64 `json:"server_mem_mib"`
	ClientCPUPct    float64 `json:"client_cpu_pct"`
	ClientMemMiB    float64 `json:"client_mem_mib"`

	// integrity
	IntegrityOK *bool `json:"integrity_ok,omitempty"`

	// diagnostics
	ErrorMsg    string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration_ms"`
	TestedAt    time.Time     `json:"tested_at"`

	// recommendation
	Recommendation string `json:"recommendation"`
}

// Report is the top-level JSON output.
type Report struct {
	Version   string        `json:"version"`
	TestedAt  time.Time     `json:"tested_at"`
	HostA     string        `json:"host_a"`
	HostB     string        `json:"host_b"`
	Overlay   string        `json:"overlay_cidr"`
	Results   []ProtoResult `json:"results"`
	Summary   ReportSummary `json:"summary"`
}

type ReportSummary struct {
	Total   int `json:"total"`
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Skipped int `json:"skipped"`
}

// ── terminal rendering ────────────────────────────────────────────────────────

const (
	colReset  = "\033[0m"
	colBold   = "\033[1m"
	colGray   = "\033[90m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
	colRed    = "\033[31m"
	colCyan   = "\033[36m"
	colBlue   = "\033[34m"
)

func isTTY() bool {
	fi, _ := os.Stdout.Stat()
	return fi != nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func c(col, s string) string {
	if !isTTY() {
		return s
	}
	return col + s + colReset
}

// PrintBanner prints the startup header.
func PrintBanner(cfg *TestConfig) {
	line := strings.Repeat("━", 72)
	fmt.Printf("\n%s\n", c(colBlue, line))
	fmt.Printf("  %s  %s\n",
		c(colBlue, "⬡"),
		c(colBold, "virlink-test v"+testVersion+"  ·  protocol benchmark suite"))
	fmt.Printf("%s\n\n", c(colBlue, line))
	fmt.Printf("  %s  %s  %s\n", c(colGray, "host A"), c(colCyan, cfg.HostA.IP), c(colGray, "(local)"))
	if cfg.HostB.IP != "" && cfg.HostB.IP != cfg.HostA.IP {
		fmt.Printf("  %s  %s  %s\n", c(colGray, "host B"), c(colCyan, cfg.HostB.IP),
			c(colGray, bkd(cfg)))
	} else {
		fmt.Printf("  %s  %s  %s\n", c(colGray, "host B"), c(colCyan, cfg.HostA.IP),
			c(colGray, "(local, same host — netns mode)"))
	}
	fmt.Printf("  %s  %s\n", c(colGray, "overlay"), c(colCyan, cfg.OverlayCIDR))
	fmt.Printf("  %s  %s\n\n", c(colGray, "backend"), cfg.Backend)
}

func bkd(cfg *TestConfig) string {
	switch cfg.Backend {
	case "ssh":
		return fmt.Sprintf("(SSH user=%s)", cfg.HostB.SSHUser)
	case "api":
		return "(api-only)"
	default:
		return "(local)"
	}
}

// PrintTableHeader prints the column header row.
func PrintTableHeader() {
	line := strings.Repeat("─", 96)
	fmt.Println(c(colGray, line))
	fmt.Printf("  %-20s  %-5s  %-7s  %12s  %12s  %9s  %5s  %5s  %5s\n",
		c(colBold, "PROTOCOL"),
		c(colBold, "DIR"),
		c(colBold, "STATUS"),
		c(colBold, "↓ DOWNLOAD"),
		c(colBold, "↑ UPLOAD"),
		c(colBold, "p50 lat"),
		c(colBold, "LOSS"),
		c(colBold, "CPU"),
		c(colBold, "MEM"),
	)
	fmt.Println(c(colGray, line))
}

// PrintRow prints a single result row.
func PrintRow(r ProtoResult) {
	status, statusCol := statusFmt(r.Status)

	dl := fmtMbps(r.DownloadMbps)
	ul := fmtMbps(r.UploadMbps)
	lat := fmtMs(r.LatencyP50Ms)
	loss := fmtLoss(r.LossPct)
	cpu := fmtPct(r.ClientCPUPct)
	mem := fmtMiB(r.ClientMemMiB)

	if r.Status != "pass" {
		dl, ul, lat, loss, cpu, mem = "—", "—", "—", "—", "—", "—"
	}

	fmt.Printf("  %-20s  %-5s  %-7s  %12s  %12s  %9s  %5s  %5s  %5s\n",
		c(colCyan, padRight(r.Protocol, 20)),
		c(colGray, string(r.Direction)),
		c(statusCol, status),
		dl, ul, lat, loss, cpu, mem,
	)

	if r.Status == "fail" || r.Status == "error" {
		fmt.Printf("    %s %s\n", c(colRed, "↳"), c(colGray, r.ErrorMsg))
	}
}

// PrintTableFooter prints the summary footer.
func PrintTableFooter(sum ReportSummary) {
	line := strings.Repeat("─", 96)
	fmt.Println(c(colGray, line))
	total := c(colGray, fmt.Sprintf("total=%d", sum.Total))
	pass := c(colGreen, fmt.Sprintf("pass=%d", sum.Pass))
	fail := c(colRed, fmt.Sprintf("fail=%d", sum.Fail))
	skip := c(colGray, fmt.Sprintf("skip=%d", sum.Skipped))
	fmt.Printf("  %s  %s  %s  %s\n\n", total, pass, fail, skip)
}

// PrintRecommendations prints the recommendation section.
func PrintRecommendations(results []ProtoResult) {
	line := strings.Repeat("━", 72)
	fmt.Printf("\n%s\n", c(colBlue, line))
	fmt.Printf("  %s\n\n", c(colBold, "Recommendations"))
	for _, r := range results {
		if r.Direction != DirAB {
			continue // only print once per protocol
		}
		icon := "⬡"
		col := colGray
		if r.Status == "pass" {
			icon = "✓"
			col = colGreen
		} else if r.Status == "fail" || r.Status == "error" {
			icon = "✗"
			col = colRed
		}
		fmt.Printf("  %s  %s%s%s\n",
			c(col, icon),
			c(colBold, padRight(r.Protocol, 18)),
			c(colGray, "  "),
			r.Recommendation,
		)
	}
	fmt.Printf("\n%s\n\n", c(colBlue, line))
}

// ── JSON report ───────────────────────────────────────────────────────────────

func WriteJSONReport(path string, report *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ── scoring / recommendations ─────────────────────────────────────────────────

// buildRecommendation generates a short recommendation string based on metrics.
func buildRecommendation(r *ProtoResult, cfg *TestConfig) string {
	if r.Status == "skip" {
		return "skipped — kernel module not available or excluded by --only flag"
	}
	if r.Status != "pass" {
		return fmt.Sprintf("not recommended — test failed: %s", r.ErrorMsg)
	}

	// score by throughput + latency
	avgMbps := (r.DownloadMbps + r.UploadMbps) / 2
	switch {
	case avgMbps > 800 && r.LatencyP50Ms < 2:
		return fmt.Sprintf("✓ production-ready — %.0f Mbps avg, %.1f ms p50", avgMbps, r.LatencyP50Ms)
	case avgMbps > 400 && r.LatencyP50Ms < 5:
		return fmt.Sprintf("✓ good — %.0f Mbps avg, consider kernel tunnel if higher throughput needed", avgMbps)
	case avgMbps > 100 && r.LossPct < 1:
		return fmt.Sprintf("○ moderate — %.0f Mbps avg; tune socket buffers or use bonded variant", avgMbps)
	case r.LossPct > 2:
		return fmt.Sprintf("⚠ lossy — %.1f%% packet loss; check MTU and kernel buffer settings", r.LossPct)
	default:
		return fmt.Sprintf("○ acceptable — %.0f Mbps avg; monitor under production load", avgMbps)
	}
}

// computeSummary tallies pass/fail/skip.
func computeSummary(results []ProtoResult) ReportSummary {
	var s ReportSummary
	s.Total = len(results)
	for _, r := range results {
		switch r.Status {
		case "pass":
			s.Pass++
		case "skip":
			s.Skipped++
		default:
			s.Fail++
		}
	}
	return s
}

// ── formatting helpers ────────────────────────────────────────────────────────

func statusFmt(s string) (string, string) {
	switch s {
	case "pass":
		return "✓ pass", colGreen
	case "fail":
		return "✗ FAIL", colRed
	case "error":
		return "✗ ERR ", colRed
	case "skip":
		return "— skip", colGray
	default:
		return s, colGray
	}
}

func fmtMbps(v float64) string {
	if v <= 0 || math.IsNaN(v) {
		return "—"
	}
	if v >= 1000 {
		return c(colGreen, fmt.Sprintf("%.2f Gbps", v/1000))
	}
	col := colGreen
	if v < 100 {
		col = colYellow
	}
	return c(col, fmt.Sprintf("%.1f Mbps", v))
}

func fmtMs(v float64) string {
	if v <= 0 {
		return "—"
	}
	col := colGreen
	if v > 10 {
		col = colYellow
	}
	if v > 50 {
		col = colRed
	}
	return c(col, fmt.Sprintf("%.2f ms", v))
}

func fmtLoss(v float64) string {
	if v < 0 {
		return "—"
	}
	col := colGreen
	if v > 1 {
		col = colYellow
	}
	if v > 5 {
		col = colRed
	}
	return c(col, fmt.Sprintf("%.1f%%", v))
}

func fmtPct(v float64) string {
	if v <= 0 {
		return "—"
	}
	col := colGray
	if v > 50 {
		col = colYellow
	}
	if v > 90 {
		col = colRed
	}
	return c(col, fmt.Sprintf("%.0f%%", v))
}

func fmtMiB(v float64) string {
	if v <= 0 {
		return "—"
	}
	return c(colGray, fmt.Sprintf("%.0fM", v))
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
