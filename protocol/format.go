package protocol

import (
	"encoding/json"
	"fmt"
	"io"
)

// RenderOutput formats a protocol.Output in text, json, sarif, or github format.
func RenderOutput(w io.Writer, out Output, format string) error {
	switch format {
	case "json", "":
		return json.NewEncoder(w).Encode(out)
	case "text":
		for _, f := range out.Findings {
			if _, err := fmt.Fprintf(w, "%s:%d [%s/%s] %s: %s\n", f.File, f.Line, f.Category, f.Severity, f.Rule, f.Message); err != nil {
				return err
			}
		}
		if len(out.Findings) == 0 {
			_, err := fmt.Fprintf(w, "%s: clean (0 findings)\n", out.App.Name)
			return err
		}
		return nil
	case "github":
		for _, f := range out.Findings {
			level := "warning"
			if f.Severity == SeverityHigh || f.Severity == SeverityCritical {
				level = "error"
			} else if f.Severity == SeverityInfo || f.Severity == SeverityLow {
				level = "notice"
			}
			if _, err := fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n", level, f.File, f.Line, f.Rule, f.Message); err != nil {
				return err
			}
		}
		return nil
	case "sarif":
		results := make([]map[string]any, 0, len(out.Findings))
		for _, f := range out.Findings {
			level := "warning"
			if f.Severity == SeverityHigh || f.Severity == SeverityCritical {
				level = "error"
			} else if f.Severity == SeverityInfo || f.Severity == SeverityLow {
				level = "note"
			}
			results = append(results, map[string]any{
				"ruleId":  f.Rule,
				"level":   level,
				"message": map[string]string{"text": f.Message},
				"locations": []map[string]any{{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]string{"uri": f.File},
						"region":           map[string]int{"startLine": f.Line},
					},
				}},
			})
		}
		doc := map[string]any{
			"version": "2.1.0",
			"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
			"runs": []map[string]any{{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    out.App.Name,
						"version": out.App.Version,
					},
				},
				"results": results,
			}},
		}
		return json.NewEncoder(w).Encode(doc)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
