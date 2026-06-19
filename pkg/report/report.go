package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/innervoid/anubis/pkg/scanner"
	"github.com/innervoid/anubis/pkg/utils"
)

// Generate writes a report in the specified format(s)
// format: "json", "html", "csv", "json+html", "json+csv"
func Generate(result *scanner.ScanResult, format, outputFile string, reportLevel string) error {
	formats := strings.Split(format, "+")

	for _, f := range formats {
		f = strings.TrimSpace(f)
		switch f {
		case "json":
			filename := outputFilename(outputFile, "json")
			if err := writeJSON(result, filename, reportLevel); err != nil {
				return fmt.Errorf("report: json: %w", err)
			}
			utils.LogSuccess("JSON report saved: %s", filename)
		case "html":
			filename := outputFilename(outputFile, "html")
			if err := writeHTML(result, filename, reportLevel); err != nil {
				return fmt.Errorf("report: html: %w", err)
			}
			utils.LogSuccess("HTML report saved: %s", filename)
		case "csv":
			filename := outputFilename(outputFile, "csv")
			if err := writeCSV(result, filename, reportLevel); err != nil {
				return fmt.Errorf("report: csv: %w", err)
			}
			utils.LogSuccess("CSV report saved: %s", filename)
		default:
			utils.LogWarn("Unknown report format: %s", f)
		}
	}
	return nil
}

func outputFilename(base, ext string) string {
	if base == "" {
		return fmt.Sprintf("anubis_report_%s.%s", time.Now().Format("20060102_150405"), ext)
	}
	// Strip existing extension
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[:idx]
	}
	return base + "." + ext
}

// filterFindings applies report level filtering
func filterFindings(findings []scanner.Finding, reportLevel string) []scanner.Finding {
	var filtered []scanner.Finding
	for _, f := range findings {
		switch reportLevel {
		case "basic":
			if f.Confidence == scanner.ConfidenceConfirmed {
				filtered = append(filtered, f)
			}
		case "detailed":
			if f.Confidence == scanner.ConfidenceConfirmed || f.Confidence == scanner.ConfidenceSuspected {
				filtered = append(filtered, f)
			}
		default: // comprehensive
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// --- JSON ---

func writeJSON(result *scanner.ScanResult, filename, reportLevel string) error {
	// Apply filtering
	filtered := filterFindings(result.AllFindings, reportLevel)

	// Group by severity
	bySeverity := map[string][]scanner.Finding{}
	for _, f := range filtered {
		bySeverity[string(f.Severity)] = append(bySeverity[string(f.Severity)], f)
	}

	// Group by type
	byType := map[string][]scanner.Finding{}
	for _, f := range filtered {
		byType[string(f.Type)] = append(byType[string(f.Type)], f)
	}

	// Group by endpoint
	byEndpoint := map[string][]scanner.Finding{}
	for _, f := range filtered {
		if f.Endpoint != "" {
			byEndpoint[f.Endpoint] = append(byEndpoint[f.Endpoint], f)
		}
	}

	output := map[string]interface{}{
		"meta": map[string]interface{}{
			"tool":         "Anubis Security Scanner",
			"version":      "1.0.0",
			"generated_at": time.Now().Format(time.RFC3339),
			"target":       result.Target,
			"scan_level":   result.ScanLevel,
			"report_level": reportLevel,
			"scan_duration": result.Duration.String(),
			"start_time":   result.StartTime.Format(time.RFC3339),
			"end_time":     result.EndTime.Format(time.RFC3339),
		},
		"summary":     result.Summary,
		"findings":    filtered,
		"by_severity": bySeverity,
		"by_type":     byType,
		"by_endpoint": byEndpoint,
		"modules":     result.Modules,
		"baseline":    result.BaselineData,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// --- HTML ---

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anubis Security Report — {{.Target}}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #8b949e; --accent: #e34c26;
    --critical: #f85149; --high: #d29922; --medium: #58a6ff;
    --low: #3fb950; --info: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }
  h1 { font-size: 2rem; color: var(--accent); margin-bottom: 0.25rem; }
  h2 { font-size: 1.25rem; color: var(--text); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  h3 { font-size: 1rem; color: var(--dim); margin-bottom: 0.75rem; }
  .meta { color: var(--dim); font-size: 0.875rem; margin-bottom: 2rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .stat-card .num { font-size: 2rem; font-weight: 700; }
  .stat-card .label { font-size: 0.75rem; color: var(--dim); margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .num.critical { color: var(--critical); }
  .num.high { color: var(--high); }
  .num.medium { color: var(--medium); }
  .num.low { color: var(--low); }
  .num.info { color: var(--info); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
  .finding-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .badge { font-size: 0.7rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  .badge.CRITICAL { background: var(--critical); color: #000; }
  .badge.HIGH { background: var(--high); color: #000; }
  .badge.MEDIUM { background: var(--medium); color: #000; }
  .badge.LOW { background: var(--low); color: #000; }
  .badge.INFO { background: var(--info); color: #000; }
  .badge.confirmed { background: #1f6feb; color: #fff; }
  .badge.suspected { background: #388bfd26; color: var(--medium); border: 1px solid var(--medium); }
  .badge.unlikely { background: transparent; color: var(--dim); border: 1px solid var(--border); }
  .finding-title { font-size: 1rem; font-weight: 600; }
  .finding-desc { color: var(--dim); font-size: 0.875rem; margin-bottom: 0.75rem; line-height: 1.5; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .detail-label { font-size: 0.7rem; color: var(--dim); text-transform: uppercase; margin-bottom: 0.25rem; }
  .detail-value { font-size: 0.875rem; word-break: break-all; }
  pre { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; font-size: 0.8rem; overflow-x: auto; margin-top: 0.5rem; white-space: pre-wrap; }
  .code-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 0.75rem; }
  .code-label { font-size: 0.7rem; text-transform: uppercase; margin-bottom: 0.25rem; }
  .vuln-label { color: var(--critical); }
  .secure-label { color: var(--low); }
  .remediation { background: #122d1f; border: 1px solid #1a4731; border-radius: 6px; padding: 1rem; margin-top: 0.75rem; font-size: 0.875rem; line-height: 1.6; }
  footer { margin-top: 3rem; color: var(--dim); font-size: 0.75rem; text-align: center; }
  @media (max-width: 600px) { .detail-grid, .code-grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<h1>Anubis Security Report</h1>
<div class="meta">
  Target: <strong>{{.Target}}</strong> &nbsp;|&nbsp;
  Scan Level: <strong>{{.ScanLevel}}</strong> &nbsp;|&nbsp;
  Generated: <strong>{{.GeneratedAt}}</strong> &nbsp;|&nbsp;
  Duration: <strong>{{.Duration}}</strong>
</div>

<h2>Summary</h2>
<div class="summary-grid">
  <div class="stat-card"><div class="num">{{.TotalFindings}}</div><div class="label">Total Findings</div></div>
  <div class="stat-card"><div class="num critical">{{index .BySeverity "CRITICAL"}}</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="num high">{{index .BySeverity "HIGH"}}</div><div class="label">High</div></div>
  <div class="stat-card"><div class="num medium">{{index .BySeverity "MEDIUM"}}</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="num low">{{index .BySeverity "LOW"}}</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="num info">{{index .BySeverity "INFO"}}</div><div class="label">Info</div></div>
  <div class="stat-card"><div class="num">{{.ModulesRun}}</div><div class="label">Modules Run</div></div>
</div>

<h2>Findings</h2>
{{range .Findings}}
<div class="finding">
  <div class="finding-header">
    <span class="badge {{.Severity}}">{{.Severity}}</span>
    <span class="badge {{.Confidence}}">{{.Confidence}}</span>
    <span class="finding-title">{{.Title}}</span>
  </div>
  <div class="finding-desc">{{.Description}}</div>
  <div class="detail-grid">
    {{if .Endpoint}}<div><div class="detail-label">Endpoint</div><div class="detail-value">{{.Endpoint}}</div></div>{{end}}
    {{if .Parameter}}<div><div class="detail-label">Parameter</div><div class="detail-value">{{.Parameter}}</div></div>{{end}}
    {{if .Module}}<div><div class="detail-label">Module</div><div class="detail-value">{{.Module}}</div></div>{{end}}
    {{if .OWASPMapping}}<div><div class="detail-label">OWASP</div><div class="detail-value">{{.OWASPMapping}}</div></div>{{end}}
    {{if .CVSSScore}}<div><div class="detail-label">CVSS Score</div><div class="detail-value">{{.CVSSScore}}</div></div>{{end}}
    {{if .Evidence}}<div><div class="detail-label">Evidence</div><div class="detail-value">{{.Evidence}}</div></div>{{end}}
  </div>
  {{if .Remediation}}
  <div class="remediation">
    <div class="detail-label" style="margin-bottom:0.5rem;">Remediation</div>
    {{.Remediation}}
  </div>
  {{end}}
  {{if or .VulnCode .SecureCode}}
  <div class="code-grid">
    {{if .VulnCode}}<div><div class="code-label vuln-label">Vulnerable Pattern</div><pre>{{.VulnCode}}</pre></div>{{end}}
    {{if .SecureCode}}<div><div class="code-label secure-label">Secure Pattern</div><pre>{{.SecureCode}}</pre></div>{{end}}
  </div>
  {{end}}
</div>
{{end}}

<footer>Anubis Security Scanner v1.0.0 — Inner Void Studio — Authorized Use Only</footer>
</body>
</html>`

type htmlData struct {
	Target        string
	ScanLevel     scanner.ScanLevel
	GeneratedAt   string
	Duration      string
	TotalFindings int
	ModulesRun    int
	BySeverity    map[string]int
	Findings      []scanner.Finding
}

func writeHTML(result *scanner.ScanResult, filename, reportLevel string) error {
	filtered := filterFindings(result.AllFindings, reportLevel)
	sortBySeverity(filtered)

	bySev := make(map[string]int)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		bySev[sev] = 0
	}
	for _, f := range filtered {
		bySev[string(f.Severity)]++
	}

	data := htmlData{
		Target:        result.Target,
		ScanLevel:     result.ScanLevel,
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05"),
		Duration:      result.Duration.Round(time.Second).String(),
		TotalFindings: len(filtered),
		ModulesRun:    result.Summary.ModulesRun,
		BySeverity:    bySev,
		Findings:      filtered,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

// --- CSV ---

func writeCSV(result *scanner.ScanResult, filename, reportLevel string) error {
	filtered := filterFindings(result.AllFindings, reportLevel)
	sortBySeverity(filtered)

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	_ = w.Write([]string{
		"ID", "Module", "Type", "Title", "Severity", "Confidence",
		"Endpoint", "Parameter", "Method", "OWASP", "CVSS",
		"Description", "Evidence", "Remediation", "Discovered At",
	})

	for _, finding := range filtered {
		_ = w.Write([]string{
			finding.ID,
			finding.Module,
			string(finding.Type),
			finding.Title,
			string(finding.Severity),
			string(finding.Confidence),
			finding.Endpoint,
			finding.Parameter,
			finding.Method,
			finding.OWASPMapping,
			fmt.Sprintf("%.1f", finding.CVSSScore),
			finding.Description,
			finding.Evidence,
			finding.Remediation,
			finding.DiscoveredAt.Format(time.RFC3339),
		})
	}

	return nil
}

func sortBySeverity(findings []scanner.Finding) {
	order := map[scanner.Severity]int{
		scanner.SeverityCritical: 0,
		scanner.SeverityHigh:     1,
		scanner.SeverityMedium:   2,
		scanner.SeverityLow:      3,
		scanner.SeverityInfo:     4,
	}
	sort.Slice(findings, func(i, j int) bool {
		oi := order[findings[i].Severity]
		oj := order[findings[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return findings[i].Module < findings[j].Module
	})
}

// PrintTerminalSummary prints a human-readable summary to stdout
func PrintTerminalSummary(result *scanner.ScanResult) {
	utils.PrintSeparator()
	utils.PrintHeader("Scan Complete — Summary")
	utils.PrintSeparator()

	fmt.Printf("  Target:    %s\n", result.Target)
	fmt.Printf("  Level:     %d\n", result.ScanLevel)
	fmt.Printf("  Duration:  %s\n", result.Duration.Round(time.Second))
	fmt.Printf("  Modules:   %d run, %d completed, %d failed\n\n",
		result.Summary.ModulesRun,
		result.Summary.ModulesCompleted,
		result.Summary.ModulesFailed,
	)

	utils.PrintHeader("Findings by Severity")
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	}
	for _, sev := range severities {
		count := result.Summary.BySeverity[string(sev)]
		if count > 0 {
			fmt.Printf("  %s  %d\n", utils.SeverityColor(string(sev)), count)
		}
	}

	total := result.Summary.TotalFindings
	fmt.Printf("\n  Total: %d finding(s)\n", total)
	utils.PrintSeparator()
}
