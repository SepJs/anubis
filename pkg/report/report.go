package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/innervoid/anubis/pkg/scanner"
	"github.com/innervoid/anubis/pkg/utils"
)

func Generate(result *scanner.ScanResult, format, outputFile string, reportLevel string) error {
	formats := strings.Split(format, "+")

	if err := os.MkdirAll("reports", 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	for _, f := range formats {
		f = strings.TrimSpace(f)
		switch f {
		case "json":
			filename := outputFilename(outputFile, "json")
			finalPath := filepath.Join("reports", filename)
			if err := writeJSON(result, finalPath, reportLevel); err != nil {
				return fmt.Errorf("report: json: %w", err)
			}
			utils.LogSuccess("JSON report saved: %s", finalPath)
		case "html":
			filename := outputFilename(outputFile, "html")
			finalPath := filepath.Join("reports", filename)
			if err := writeHTML(result, finalPath, reportLevel); err != nil {
				return fmt.Errorf("report: html: %w", err)
			}
			utils.LogSuccess("HTML report saved: %s", finalPath)
		case "csv":
			filename := outputFilename(outputFile, "csv")
			finalPath := filepath.Join("reports", filename)
			if err := writeCSV(result, finalPath, reportLevel); err != nil {
				return fmt.Errorf("report: csv: %w", err)
			}
			utils.LogSuccess("CSV report saved: %s", finalPath)
		}
	}
	return nil
}

func outputFilename(base, ext string) string {
	if base == "" {
		return fmt.Sprintf("anubis_report_%d.%s", time.Now().Unix(), ext)
	}
	if !strings.HasSuffix(base, "."+ext) {
		return base + "." + ext
	}
	return base
}

func writeJSON(result *scanner.ScanResult, path string, level string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func writeCSV(result *scanner.ScanResult, path string, level string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	_ = writer.Write([]string{"Module", "Severity", "Type", "Title", "Description", "Endpoint"})

	for _, f := range result.AllFindings {
		_ = writer.Write([]string{f.Module, string(f.Severity), string(f.Type), f.Title, f.Description, f.Endpoint})
	}
	return nil
}

func writeHTML(result *scanner.ScanResult, path string, level string) error {
	tmplSrc := `<!DOCTYPE html>
<html>
<head>
    <title>Anubis Security Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 1100px; margin: auto; }
        h1, h2 { color: #ff3333; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .summary-box { background: #1e1e1e; padding: 20px; border-left: 5px solid #ff3333; margin-bottom: 20px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background-color: #1a1a1a; color: #ff3333; }
        .severity-CRITICAL { color: #ff3333; font-weight: bold; }
        .severity-HIGH { color: #ff6600; font-weight: bold; }
        .severity-MEDIUM { color: #ffcc00; font-weight: bold; }
        .severity-LOW { color: #33cc33; font-weight: bold; }
        .severity-INFO { color: #0099ff; font-weight: bold; }
        .finding-row:hover { background-color: #1f1f1f; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Anubis Framework Tactical Inspection Report</h1>
        <div class="summary-box">
            <p><strong>Target:</strong> {{.Target}}</p>
            <p><strong>Scan Level:</strong> {{.ScanLevel}}</p>
            <p><strong>Duration:</strong> {{.Duration}}</p>
            <p><strong>Total Findings:</strong> {{.Summary.TotalFindings}}</p>
        </div>
        
        <h2>Vulnerability & Finding Matrix</h2>
        <table>
            <tr>
                <th>Module</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Title</th>
                <th>Endpoint</th>
            </tr>
            {{range .AllFindings}}
            <tr class="finding-row">
                <td>{{.Module}}</td>
                <td><span class="severity-{{.Severity}}">{{.Severity}}</span></td>
                <td>{{.Type}}</td>
                <td><strong>{{.Title}}</strong><br><small style="color:#aaa;">{{.Description}}</small></td>
                <td>{{if .Endpoint}}<code>{{.Endpoint}}</code>{{else}}N/A{{end}}</td>
            </tr>
            {{end}}
        </table>
    </div>
</body>
</html>`

	tmpl, err := template.New("report").Parse(tmplSrc)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	sortBySeverity(result.AllFindings)
	return tmpl.Execute(file, result)
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
	for _, s := range severities {
		fmt.Printf("  %-10s : %d\n", s, result.Summary.BySeverity[string(s)])
	}
	utils.PrintSeparator()
}
