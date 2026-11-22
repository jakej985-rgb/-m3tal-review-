package cli

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type DashboardData struct {
	TotalReviews  int
	AverageGrade  string
	AverageScore  int
	TotalFindings int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	Reports       []DashboardReportItem
}

type DashboardReportItem struct {
	RunID     string
	Timestamp string
	Branch    string
	Grade     string
	Score     int
	Findings  int
	Passed    bool
}

func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// LoadDashboardData reads and aggregates report artifacts from .m3tal-review/reports.
func LoadDashboardData(repoRoot string) (*DashboardData, error) {
	reportsDir := filepath.Join(repoRoot, ".m3tal-review", "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &DashboardData{AverageGrade: "A", AverageScore: 100}, nil
		}
		return nil, err
	}

	data := &DashboardData{}
	totalScore := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(reportsDir, entry.Name())
		rep, err := review.ReadReport(path)
		if err != nil {
			continue
		}

		gradeStr := "A"
		scoreVal := 100
		if rep.Grade != nil {
			gradeStr = rep.Grade.Grade
			scoreVal = rep.Grade.Score
		} else {
			gr := review.ComputeGrade(rep.Findings)
			gradeStr = gr.Grade
			scoreVal = gr.Score
		}

		data.TotalReviews++
		totalScore += scoreVal
		data.TotalFindings += len(rep.Findings)

		for _, f := range rep.Findings {
			switch strings.ToLower(f.Severity) {
			case "critical":
				data.CriticalCount++
			case "high":
				data.HighCount++
			case "medium":
				data.MediumCount++
			case "low":
				data.LowCount++
			}
		}

		timeStr := rep.RunID
		if len(timeStr) > 8 {
			timeStr = timeStr[:8]
		}

		data.Reports = append(data.Reports, DashboardReportItem{
			RunID:     rep.RunID,
			Timestamp: timeStr,
			Branch:    rep.Branch,
			Grade:     gradeStr,
			Score:     scoreVal,
			Findings:  len(rep.Findings),
			Passed:    rep.Passed,
		})
	}

	if data.TotalReviews > 0 {
		data.AverageScore = totalScore / data.TotalReviews
		data.AverageGrade = scoreToGrade(data.AverageScore)
	} else {
		data.AverageGrade = "A"
		data.AverageScore = 100
	}

	// Sort newest runs first
	sort.Slice(data.Reports, func(i, j int) bool {
		return data.Reports[i].RunID > data.Reports[j].RunID
	})

	return data, nil
}

const dashboardHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>M3TAL Review — Platform Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; }
    h1 { margin: 0; font-size: 24px; color: #58a6ff; }
    .badge { background: #238636; color: #fff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
    .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }
    .card-title { font-size: 12px; color: #8b949e; text-transform: uppercase; margin-bottom: 8px; }
    .card-value { font-size: 28px; font-weight: bold; color: #f0f6fc; }
    .grade-A { color: #3fb950; }
    .grade-B { color: #d29922; }
    .grade-C { color: #db6d28; }
    .grade-F { color: #f85149; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 6px; overflow: hidden; }
    th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #21262d; }
    th { background: #21262d; color: #8b949e; font-size: 13px; font-weight: 600; }
    tr:hover { background: #1c2128; }
    .status-pass { color: #3fb950; font-weight: 600; }
    .status-fail { color: #f85149; font-weight: 600; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ M3TAL Review Platform Dashboard</h1>
    <span class="badge">Local Deterministic Engine</span>
  </div>

  <div class="metrics">
    <div class="card">
      <div class="card-title">Average Grade</div>
      <div class="card-value grade-{{.AverageGrade}}">{{.AverageGrade}} ({{.AverageScore}}/100)</div>
    </div>
    <div class="card">
      <div class="card-title">Total Reviews</div>
      <div class="card-value">{{.TotalReviews}}</div>
    </div>
    <div class="card">
      <div class="card-title">Total Findings</div>
      <div class="card-value">{{.TotalFindings}}</div>
    </div>
    <div class="card">
      <div class="card-title">Critical / High Issues</div>
      <div class="card-value" style="color: #f85149;">{{.CriticalCount}} / {{.HighCount}}</div>
    </div>
  </div>

  <h2>Recent Review Reports</h2>
  <table>
    <thead>
      <tr>
        <th>Run ID</th>
        <th>Branch</th>
        <th>Grade</th>
        <th>Score</th>
        <th>Findings</th>
        <th>Verdict</th>
      </tr>
    </thead>
    <tbody>
      {{range .Reports}}
      <tr>
        <td><code>{{.RunID}}</code></td>
        <td>{{.Branch}}</td>
        <td class="grade-{{.Grade}}"><strong>{{.Grade}}</strong></td>
        <td>{{.Score}}</td>
        <td>{{.Findings}}</td>
        <td>
          {{if .Passed}}
            <span class="status-pass">Passed</span>
          {{else}}
            <span class="status-fail">Action Required</span>
          {{end}}
        </td>
      </tr>
      {{else}}
      <tr>
        <td colspan="6" style="text-align: center; color: #8b949e;">No review reports found in <code>.m3tal-review/reports</code>.</td>
      </tr>
      {{end}}
    </tbody>
  </table>
</body>
</html>
`

// StartDashboardServer launches the local dashboard HTTP handler.
func StartDashboardServer(repoRoot string, port int) error {
	tmpl, err := template.New("dashboard").Parse(dashboardHTMLTemplate)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := LoadDashboardData(repoRoot)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	})

	mux.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		data, err := LoadDashboardData(repoRoot)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data)
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("M3TAL Review Dashboard listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}
