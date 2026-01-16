// internal/reporters/manager.go
package reporters

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"incident-analyzer/internal/analyzer"
)

type Manager struct {
	outputDir string
}

func NewManager(outputDir string) *Manager {
	return &Manager{outputDir: outputDir}
}

func (m *Manager) GenerateTerminal(result *analyzer.AnalysisResult) error {
	return generateTerminalReport(result)
}

func (m *Manager) GenerateMarkdown(result *analyzer.AnalysisResult) error {
	path := filepath.Join(m.outputDir, "INCIDENT_REPORT.md")
	return generateMarkdownReport(result, path)
}

func (m *Manager) GenerateHTML(result *analyzer.AnalysisResult) (string, error) {
	path := filepath.Join(m.outputDir, "report.html")
	return path, generateHTMLReport(result, path)
}

func OpenInBrowser(path string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}

	return cmd.Start()
}

// internal/reporters/terminal.go
package reporters

import (
	"fmt"
	"strings"

	"incident-analyzer/internal/analyzer"
)

func generateTerminalReport(result *analyzer.AnalysisResult) error {
	fmt.Println()
	fmt.Println(strings.Repeat("━", 70))
	
	if result.RootCause != nil {
		fmt.Println("🚨 ROOT CAUSE IDENTIFIED")
		fmt.Println(strings.Repeat("━", 70))
		fmt.Println()
		fmt.Printf("Pattern: %s\n", result.RootCause.Pattern)
		fmt.Printf("Confidence: %.0f%%\n", result.RootCause.Confidence*100)
		fmt.Printf("First Detected: %s\n", result.RootCause.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Println()
		fmt.Printf("Description: %s\n", result.RootCause.Description)
		fmt.Println()
		
		if len(result.RootCause.Evidence) > 0 {
			fmt.Println("Evidence:")
			for _, evidence := range result.RootCause.Evidence {
				fmt.Printf("  • %s\n", evidence)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("ℹ️  ANALYSIS SUMMARY")
		fmt.Println(strings.Repeat("━", 70))
		fmt.Println()
		fmt.Println("No definitive root cause identified")
		fmt.Println()
	}

	// Summary statistics
	fmt.Println("📊 SUMMARY")
	fmt.Println(strings.Repeat("━", 70))
	fmt.Printf("Total Events: %d\n", result.Summary.TotalEvents)
	fmt.Printf("Errors: %d (%.1f%%)\n", result.Summary.ErrorCount, result.Summary.ErrorRate)
	fmt.Printf("Warnings: %d\n", result.Summary.WarningCount)
	fmt.Printf("Duration: %s\n", result.Summary.Duration)
	
	if len(result.Summary.AffectedSources) > 0 {
		fmt.Printf("Affected Sources: %s\n", strings.Join(result.Summary.AffectedSources, ", "))
	}
	fmt.Println()

	// Patterns
	if len(result.Patterns) > 0 {
		fmt.Println("🔍 DETECTED PATTERNS")
		fmt.Println(strings.Repeat("━", 70))
		for _, pattern := range result.Patterns {
			severity := "  "
			if pattern.Severity == "CRITICAL" {
				severity = "🔴"
			} else if pattern.Severity == "HIGH" {
				severity = "🟡"
			}
			fmt.Printf("%s %-40s (%d occurrences)\n", severity, pattern.Name, pattern.Occurrences)
			fmt.Printf("   First: %s | Last: %s\n", 
				pattern.FirstSeen.Format("15:04:05"), 
				pattern.LastSeen.Format("15:04:05"))
		}
		fmt.Println()
	}

	// Anomalies
	if len(result.Anomalies) > 0 {
		fmt.Println("⚠️  ANOMALIES DETECTED")
		fmt.Println(strings.Repeat("━", 70))
		for _, anomaly := range result.Anomalies {
			fmt.Printf("• %s: %s\n", anomaly.Type, anomaly.Description)
		}
		fmt.Println()
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		fmt.Println("📋 RECOMMENDATIONS")
		fmt.Println(strings.Repeat("━", 70))
		for _, rec := range result.Recommendations {
			if rec == "" {
				fmt.Println()
			} else if !strings.HasPrefix(rec, " ") {
				fmt.Println(rec)
			} else {
				fmt.Println(rec)
			}
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("━", 70))
	
	return nil
}

// internal/reporters/markdown.go
package reporters

import (
	"fmt"
	"os"
	"strings"

	"incident-analyzer/internal/analyzer"
)

func generateMarkdownReport(result *analyzer.AnalysisResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# Incident Analysis Report\n\n")
	fmt.Fprintf(f, "**Generated:** %s\n\n", result.Summary.TimeRange.End.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "**Time Window:** %s → %s (%s)\n\n",
		result.Summary.TimeRange.Start.Format("2006-01-02 15:04"),
		result.Summary.TimeRange.End.Format("2006-01-02 15:04"),
		result.Summary.Duration)

	fmt.Fprintf(f, "---\n\n")

	// Root Cause
	if result.RootCause != nil {
		fmt.Fprintf(f, "## 🚨 Root Cause\n\n")
		fmt.Fprintf(f, "**Pattern:** %s  \n", result.RootCause.Pattern)
		fmt.Fprintf(f, "**Confidence:** %.0f%%  \n", result.RootCause.Confidence*100)
		fmt.Fprintf(f, "**First Detected:** %s  \n\n", result.RootCause.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(f, "**Description:** %s\n\n", result.RootCause.Description)
		
		if len(result.RootCause.Evidence) > 0 {
			fmt.Fprintf(f, "### Evidence\n\n")
			for _, evidence := range result.RootCause.Evidence {
				fmt.Fprintf(f, "- %s\n", evidence)
			}
			fmt.Fprintf(f, "\n")
		}

		fmt.Fprintf(f, "### Resolution Steps\n\n")
		fmt.Fprintf(f, "```\n%s\n```\n\n", result.RootCause.Resolution)
	}

	// Summary
	fmt.Fprintf(f, "## 📊 Summary\n\n")
	fmt.Fprintf(f, "| Metric | Value |\n")
	fmt.Fprintf(f, "|--------|-------|\n")
	fmt.Fprintf(f, "| Total Events | %d |\n", result.Summary.TotalEvents)
	fmt.Fprintf(f, "| Errors | %d (%.1f%%) |\n", result.Summary.ErrorCount, result.Summary.ErrorRate)
	fmt.Fprintf(f, "| Warnings | %d |\n", result.Summary.WarningCount)
	fmt.Fprintf(f, "| Duration | %s |\n", result.Summary.Duration)
	fmt.Fprintf(f, "\n")

	// Patterns
	if len(result.Patterns) > 0 {
		fmt.Fprintf(f, "## 🔍 Detected Patterns\n\n")
		fmt.Fprintf(f, "| Pattern | Severity | Occurrences | First Seen | Last Seen |\n")
		fmt.Fprintf(f, "|---------|----------|-------------|------------|----------|\n")
		for _, pattern := range result.Patterns {
			fmt.Fprintf(f, "| %s | %s | %d | %s | %s |\n",
				pattern.Name,
				pattern.Severity,
				pattern.Occurrences,
				pattern.FirstSeen.Format("15:04:05"),
				pattern.LastSeen.Format("15:04:05"))
		}
		fmt.Fprintf(f, "\n")
	}

	// Anomalies
	if len(result.Anomalies) > 0 {
		fmt.Fprintf(f, "## ⚠️ Anomalies\n\n")
		for _, anomaly := range result.Anomalies {
			fmt.Fprintf(f, "### %s\n\n", anomaly.Type)
			fmt.Fprintf(f, "%s\n\n", anomaly.Description)
		}
	}

	// Top Errors
	if len(result.Statistics.TopErrors) > 0 {
		fmt.Fprintf(f, "## 🔴 Top Errors\n\n")
		fmt.Fprintf(f, "| Count | Message | Sources |\n")
		fmt.Fprintf(f, "|-------|---------|----------|\n")
		for _, err := range result.Statistics.TopErrors {
			fmt.Fprintf(f, "| %d | %s | %s |\n",
				err.Count,
				err.Message,
				strings.Join(err.Sources, ", "))
		}
		fmt.Fprintf(f, "\n")
	}

	// Recommendations
	if len(result.Recommendations) > 0 {
		fmt.Fprintf(f, "## 📋 Recommendations\n\n")
		for _, rec := range result.Recommendations {
			if rec == "" {
				fmt.Fprintf(f, "\n")
			} else if strings.HasPrefix(rec, " ") {
				fmt.Fprintf(f, "%s\n", rec)
			} else {
				fmt.Fprintf(f, "**%s**\n\n", rec)
			}
		}
	}

	return nil
}

// internal/reporters/html.go
package reporters

import (
	"fmt"
	"os"
	"strings"

	"incident-analyzer/internal/analyzer"
)

func generateHTMLReport(result *analyzer.AnalysisResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Incident Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { font-size: 32px; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; font-size: 14px; }
        .section { padding: 30px; border-bottom: 1px solid #eee; }
        .section:last-child { border-bottom: none; }
        .section h2 { color: #333; margin-bottom: 20px; font-size: 24px; }
        .root-cause { background: #fff3cd; border-left: 4px solid #ff6b6b; padding: 20px; border-radius: 4px; margin-bottom: 20px; }
        .root-cause h3 { color: #d63031; margin-bottom: 10px; }
        .confidence { display: inline-block; background: #00b894; color: white; padding: 4px 12px; border-radius: 12px; font-size: 14px; font-weight: bold; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; }
        .stat-card .label { color: #666; font-size: 14px; margin-bottom: 5px; }
        .stat-card .value { font-size: 28px; font-weight: bold; color: #333; }
        .pattern { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #feca57; }
        .pattern.critical { border-left-color: #ff6b6b; }
        .pattern.high { border-left-color: #feca57; }
        .pattern-name { font-weight: bold; color: #333; margin-bottom: 5px; }
        .pattern-meta { color: #666; font-size: 14px; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #333; }
        .recommendations { background: #e3f2fd; padding: 20px; border-radius: 4px; border-left: 4px solid #2196f3; }
        .recommendations ul { margin-left: 20px; margin-top: 10px; }
        .recommendations li { margin: 8px 0; color: #333; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge.critical { background: #ff6b6b; color: white; }
        .badge.high { background: #feca57; color: #333; }
        .badge.error { background: #e74c3c; color: white; }
        .badge.warn { background: #f39c12; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Incident Analysis Report</h1>
            <div class="meta">
                Generated: %s<br>
                Time Window: %s → %s (%s)
            </div>
        </div>
`,
		result.Summary.TimeRange.End.Format("2006-01-02 15:04:05"),
		result.Summary.TimeRange.Start.Format("2006-01-02 15:04"),
		result.Summary.TimeRange.End.Format("2006-01-02 15:04"),
		result.Summary.Duration)

	// Root Cause Section
	if result.RootCause != nil {
		fmt.Fprintf(f, `
        <div class="section">
            <h2>🚨 Root Cause</h2>
            <div class="root-cause">
                <h3>%s</h3>
                <p><span class="confidence">%.0f%% Confidence</span></p>
                <p style="margin: 15px 0;"><strong>First Detected:</strong> %s</p>
                <p style="margin-bottom: 15px;">%s</p>
                <details>
                    <summary style="cursor: pointer; font-weight: bold; margin-bottom: 10px;">Resolution Steps</summary>
                    <pre style="background: white; padding: 15px; border-radius: 4px; overflow-x: auto;">%s</pre>
                </details>
            </div>
        </div>
`,
			result.RootCause.Pattern,
			result.RootCause.Confidence*100,
			result.RootCause.Timestamp.Format("2006-01-02 15:04:05"),
			result.RootCause.Description,
			result.RootCause.Resolution)
	}

	// Statistics Section
	fmt.Fprintf(f, `
        <div class="section">
            <h2>📊 Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="label">Total Events</div>
                    <div class="value">%s</div>
                </div>
                <div class="stat-card">
                    <div class="label">Errors</div>
                    <div class="value">%s</div>
                </div>
                <div class="stat-card">
                    <div class="label">Error Rate</div>
                    <div class="value">%.1f%%</div>
                </div>
                <div class="stat-card">
                    <div class="label">Warnings</div>
                    <div class="value">%s</div>
                </div>
            </div>
        </div>
`,
		formatNumber(result.Summary.TotalEvents),
		formatNumber(result.Summary.ErrorCount),
		result.Summary.ErrorRate,
		formatNumber(result.Summary.WarningCount))

	// Patterns Section
	if len(result.Patterns) > 0 {
		fmt.Fprintf(f, `
        <div class="section">
            <h2>🔍 Detected Patterns</h2>
`)
		for _, pattern := range result.Patterns {
			severityClass := strings.ToLower(pattern.Severity)
			fmt.Fprintf(f, `
            <div class="pattern %s">
                <div class="pattern-name">%s <span class="badge %s">%s</span></div>
                <div class="pattern-meta">
                    %d occurrences | First: %s | Last: %s
                </div>
                <p style="margin-top: 10px; color: #666;">%s</p>
            </div>
`,
				severityClass,
				pattern.Name,
				severityClass,
				pattern.Severity,
				pattern.Occurrences,
				pattern.FirstSeen.Format("15:04:05"),
				pattern.LastSeen.Format("15:04:05"),
				pattern.Description)
		}
		fmt.Fprintf(f, `        </div>
`)
	}

	// Recommendations Section
	if len(result.Recommendations) > 0 {
		fmt.Fprintf(f, `
        <div class="section">
            <h2>📋 Recommendations</h2>
            <div class="recommendations">
                <ul>
`)
		for _, rec := range result.Recommendations {
			if rec != "" && !strings.HasPrefix(rec, " ") {
				fmt.Fprintf(f, "                    <li><strong>%s</strong></li>\n", rec)
			} else if rec != "" {
				fmt.Fprintf(f, "                    <li>%s</li>\n", strings.TrimSpace(rec))
			}
		}
		fmt.Fprintf(f, `                </ul>
            </div>
        </div>
`)
	}

	fmt.Fprintf(f, `
    </div>
</body>
</html>
`)

	return nil
}

func formatNumber(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1000000)
}