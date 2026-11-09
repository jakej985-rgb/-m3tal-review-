package review

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// Supported framework identifiers
const (
	FrameworkGin     = "gin"
	FrameworkEcho    = "echo"
	FrameworkChi     = "chi"
	FrameworkFiber   = "fiber"
	FrameworkNetHTTP = "net/http"
)

const FrameworkPackVersion = "1.0.0"

// FrameworkPack represents a versioned set of domain-specific rules for a Go web framework.
type FrameworkPack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Rules       []Rule `json:"-"`
}

var (
	importGinRe     = regexp.MustCompile(`"(?:github\.com/gin-gonic/gin)"`)
	importEchoRe    = regexp.MustCompile(`"(?:github\.com/labstack/echo(?:/v\d+)?)"`)
	importChiRe     = regexp.MustCompile(`"(?:github\.com/go-chi/chi(?:/v\d+)?)"`)
	importFiberRe   = regexp.MustCompile(`"(?:github\.com/gofiber/fiber(?:/v\d+)?)"`)
	importNetHTTPRe = regexp.MustCompile(`"net/http"`)

	modGinRe   = regexp.MustCompile(`(?m)^\s*require\s+([^\s]*github\.com/gin-gonic/gin|github\.com/gin-gonic/gin\s+)`)
	modEchoRe  = regexp.MustCompile(`(?m)^\s*require\s+([^\s]*github\.com/labstack/echo|github\.com/labstack/echo(?:/v\d+)?\s+)`)
	modChiRe   = regexp.MustCompile(`(?m)^\s*require\s+([^\s]*github\.com/go-chi/chi|github\.com/go-chi/chi(?:/v\d+)?\s+)`)
	modFiberRe = regexp.MustCompile(`(?m)^\s*require\s+([^\s]*github\.com/gofiber/fiber|github\.com/gofiber/fiber(?:/v\d+)?\s+)`)

	// Block-require fallback in go.mod
	blockModGinRe   = regexp.MustCompile(`(?m)^\s*github\.com/gin-gonic/gin\s+`)
	blockModEchoRe  = regexp.MustCompile(`(?m)^\s*github\.com/labstack/echo(?:/v\d+)?\s+`)
	blockModChiRe   = regexp.MustCompile(`(?m)^\s*github\.com/go-chi/chi(?:/v\d+)?\s+`)
	blockModFiberRe = regexp.MustCompile(`(?m)^\s*github\.com/gofiber/fiber(?:/v\d+)?\s+`)
)

// GinPack returns the versioned rule pack for the Gin web framework.
func GinPack(repoRoot string) FrameworkPack {
	rules := []Rule{
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "gin-unhandled-binding",
			severity:    "medium",
			remediation: "Check error returned by c.ShouldBind/Bind: if err := c.ShouldBindJSON(&req); err != nil { c.AbortWithStatusJSON(400, ...); return }",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:_\s*=\s*c\.(?:ShouldBind|Bind)\w*\s*\(|^\s*c\.(?:ShouldBind|Bind)\w*\s*\([^)]*\)\s*$)`),
					message:  "Unhandled Gin binding error; request payload validation failure will be ignored",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "gin-wildcard-cors",
			severity:    "high",
			raw:         true,
			remediation: "Configure explicit allowed origins rather than wildcard '*' when AllowCredentials is true.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:cors\.Default\(\)|AllowAllOrigins:\s*true|AllowOrigins:\s*\[\]string\{"\*"\}|AllowOrigins:\s*\[\]string\{[^}]*"\*"[^}]*\}[^;]{0,120}?AllowCredentials:\s*true)`),
					message:  "Gin CORS configuration allows wildcard origin with credentials enabled",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "gin-missing-recovery",
			severity:    "medium",
			remediation: "Add r.Use(gin.Recovery()) to recover from panics and return a 500 error.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bgin\.New\(\)`),
					message:  "Gin engine initialized with gin.New() without Recovery middleware; unhandled panics will crash the server",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "gin-unsafe-param-reflection",
			severity:    "high",
			remediation: "Sanitize route parameters before writing to response, or use typed JSON responses.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bc\.(?:String|Writer\.Write(?:String)?|HTML)\s*\([^;]{0,160}?\bc\.(?:Param|Query)\s*\(`),
					message:  "Gin route parameter or query reflected directly into response body; risk of XSS or response splitting",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "gin-debug-mode",
			severity:    "low",
			remediation: "Use gin.SetMode(gin.ReleaseMode) or configure mode via the GIN_MODE environment variable in production.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bgin\.SetMode\s*\(\s*gin\.DebugMode\s*\)`),
					message:  "Gin debug mode enabled explicitly; verbose internal routing details and headers may be leaked",
				},
			},
		},
	}
	return FrameworkPack{
		ID:          FrameworkGin,
		Name:        "Gin",
		Version:     FrameworkPackVersion,
		Description: "Domain-specific security and correctness rules for the Gin web framework",
		Rules:       rules,
	}
}

// EchoPack returns the versioned rule pack for the Echo web framework.
func EchoPack(repoRoot string) FrameworkPack {
	rules := []Rule{
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "echo-unhandled-binding",
			severity:    "medium",
			remediation: "Check error: if err := c.Bind(&req); err != nil { return echo.NewHTTPError(http.StatusBadRequest, err.Error()) }",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:_\s*=\s*c\.Bind\s*\(|^\s*c\.Bind\s*\([^)]*\)\s*$)`),
					message:  "Unhandled Echo binding error; unvalidated input continues execution",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "echo-wildcard-cors",
			severity:    "high",
			raw:         true,
			remediation: "Specify explicit origins in AllowOrigins when AllowCredentials is true.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:AllowOrigins:\s*\[\]string\{"\*"\}|middleware\.DefaultCORSConfig)`),
					message:  "Echo CORS configuration allows wildcard origin with credentials enabled",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "echo-missing-recovery",
			severity:    "medium",
			remediation: "Add e.Use(middleware.Recover()) to protect against panic crashes.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\becho\.New\(\)`),
					message:  "Echo instance created without Recover middleware; panics in handlers will crash the server",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "echo-unsafe-param-reflection",
			severity:    "high",
			remediation: "Sanitize route parameters or use secure templates/JSON responses.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bc\.(?:HTML|String|Blob|Response\(\)\.Write(?:String)?)\s*\([^;]{0,160}?\bc\.(?:Param|QueryParam)\s*\(`),
					message:  "Echo route parameter reflected directly in response body without sanitization",
				},
			},
		},
	}
	return FrameworkPack{
		ID:          FrameworkEcho,
		Name:        "Echo",
		Version:     FrameworkPackVersion,
		Description: "Domain-specific security and correctness rules for the Echo web framework",
		Rules:       rules,
	}
}

// ChiPack returns the versioned rule pack for the Chi router framework.
func ChiPack(repoRoot string) FrameworkPack {
	rules := []Rule{
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "chi-unhandled-binding",
			severity:    "medium",
			remediation: "Check error returned by render.Bind: if err := render.Bind(r, &req); err != nil { render.Render(w, r, ...); return }",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:_\s*=\s*render\.(?:Bind|Decode)\w*\s*\(|^\s*render\.(?:Bind|Decode\w*)\s*\([^)]*\)\s*$)`),
					message:  "Unhandled Chi render.Bind or Decode error; invalid request payloads may trigger runtime errors",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "chi-wildcard-cors",
			severity:    "high",
			raw:         true,
			remediation: "Restrict AllowedOrigins to specific trusted origins rather than wildcard '*'.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:AllowedOrigins:\s*\[\]string\{"\*"\}|AllowedOrigins:\s*\[\]string\{[^}]*"\*"[^}]*\}[^;]{0,120}?AllowCredentials:\s*true)`),
					message:  "Chi CORS middleware allows wildcard origin with AllowCredentials enabled",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "chi-missing-recovery",
			severity:    "medium",
			remediation: "Add r.Use(middleware.Recoverer) to router middleware chain.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bchi\.NewRouter\(\)`),
					message:  "Chi router initialized without middleware.Recoverer; uncaught panics will crash the process",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "chi-unsafe-param-reflection",
			severity:    "high",
			remediation: "Sanitize URL parameters before writing to response or use html/template escaping.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:w\.Write|fmt\.Fprintf\s*\(\s*w)\s*\([^;]{0,160}?\bchi\.URLParam\s*\(`),
					message:  "Chi URLParam reflected directly into response writer without sanitization",
				},
			},
		},
	}
	return FrameworkPack{
		ID:          FrameworkChi,
		Name:        "Chi",
		Version:     FrameworkPackVersion,
		Description: "Domain-specific security and correctness rules for the Chi routing framework",
		Rules:       rules,
	}
}

// FiberPack returns the versioned rule pack for the Fiber web framework.
func FiberPack(repoRoot string) FrameworkPack {
	rules := []Rule{
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "fiber-unhandled-binding",
			severity:    "medium",
			remediation: "Check error: if err := c.BodyParser(&req); err != nil { return c.Status(fiber.StatusBadRequest).SendString(err.Error()) }",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:_\s*=\s*c\.(?:BodyParser|QueryParser|ParamsInt)\s*\(|^\s*c\.(?:BodyParser|QueryParser)\s*\([^)]*\)\s*$)`),
					message:  "Unhandled Fiber BodyParser or QueryParser error; invalid input will not be rejected",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "fiber-wildcard-cors",
			severity:    "high",
			raw:         true,
			remediation: "Specify explicit origins in AllowOrigins rather than '*' when AllowCredentials is true.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:AllowOrigins:\s*"[*]"[^;]{0,120}?AllowCredentials:\s*true|AllowCredentials:\s*true[^;]{0,120}?AllowOrigins:\s*"[*]")`),
					message:  "Fiber CORS middleware allows wildcard '*' origin with AllowCredentials enabled",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "fiber-missing-recovery",
			severity:    "medium",
			remediation: "Add app.Use(recover.New()) after creating the Fiber app.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bfiber\.New\(\)`),
					message:  "Fiber application created without recover middleware; handler panics will terminate the process",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "fiber-unsafe-param-reflection",
			severity:    "high",
			remediation: "Sanitize route parameters before writing to response.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bc\.(?:SendString|Send|Format)\s*\([^;]{0,160}?\bc\.Params\s*\(`),
					message:  "Fiber route parameter reflected directly in response body without sanitization",
				},
			},
		},
	}
	return FrameworkPack{
		ID:          FrameworkFiber,
		Name:        "Fiber",
		Version:     FrameworkPackVersion,
		Description: "Domain-specific security and correctness rules for the Fiber web framework",
		Rules:       rules,
	}
}

// NetHTTPPack returns the versioned rule pack for standard net/http.
func NetHTTPPack(repoRoot string) FrameworkPack {
	rules := []Rule{
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "http-unhandled-body-read",
			severity:    "medium",
			remediation: "Check decode error: if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, err.Error(), 400); return }",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:_\s*=\s*json\.NewDecoder\s*\(\s*r\.Body\s*\)\.Decode\s*\(|^\s*json\.NewDecoder\s*\(\s*r\.Body\s*\)\.Decode\s*\([^)]*\)\s*$)`),
					message:  "Unhandled json.NewDecoder.Decode error on HTTP request body",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "http-wildcard-cors",
			severity:    "high",
			raw:         true,
			remediation: "Do not combine wildcard CORS origin with credentials.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?s)Header\(\)\.Set\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*"\*"\s*\).*?Header\(\)\.Set\s*\(\s*"Access-Control-Allow-Credentials"\s*,\s*"true"\s*\)|(?s)Header\(\)\.Set\s*\(\s*"Access-Control-Allow-Credentials"\s*,\s*"true"\s*\).*?Header\(\)\.Set\s*\(\s*"Access-Control-Allow-Origin"\s*,\s*"\*"\s*\)`),
					message:  "Wildcard Access-Control-Allow-Origin '*' combined with Access-Control-Allow-Credentials true",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "http-missing-timeouts",
			severity:    "medium",
			remediation: "Configure explicit ReadTimeout and WriteTimeout on http.Server.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`\bhttp\.ListenAndServe\s*\(`),
					message:  "HTTP server created with default http.ListenAndServe without ReadTimeout/WriteTimeout; vulnerable to slowloris DoS",
				},
			},
		},
		&patternRule{
			ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
			name:        "http-unsafe-param-reflection",
			severity:    "high",
			remediation: "Sanitize or escape request parameters before writing to response writer.",
			patterns: []langPattern{
				{
					language: language.LanguageGo,
					pattern:  regexp.MustCompile(`(?:w\.Write|fmt\.Fprintf\s*\(\s*w)\s*\([^;]{0,160}?(?:r\.PathValue|r\.URL\.Query\(\)\.Get)\s*\(`),
					message:  "HTTP request parameter reflected directly in response without HTML escaping or sanitization",
				},
			},
		},
	}
	return FrameworkPack{
		ID:          FrameworkNetHTTP,
		Name:        "net/http",
		Version:     FrameworkPackVersion,
		Description: "Domain-specific security and correctness rules for standard net/http",
		Rules:       rules,
	}
}

// AllFrameworkPacks returns all supported framework packs.
func AllFrameworkPacks(repoRoot string) []FrameworkPack {
	return []FrameworkPack{
		GinPack(repoRoot),
		EchoPack(repoRoot),
		ChiPack(repoRoot),
		FiberPack(repoRoot),
		NetHTTPPack(repoRoot),
	}
}

// DetectFrameworks detects web frameworks in use from go.mod and source code / diff imports.
func DetectFrameworks(repoRoot string, diff string) []string {
	detected := make(map[string]bool)

	// 1. Inspect go.mod if present
	if repoRoot != "" {
		modPath := filepath.Join(repoRoot, "go.mod")
		if modData, err := os.ReadFile(modPath); err == nil {
			modContent := string(modData)
			if modGinRe.MatchString(modContent) || blockModGinRe.MatchString(modContent) {
				detected[FrameworkGin] = true
			}
			if modEchoRe.MatchString(modContent) || blockModEchoRe.MatchString(modContent) {
				detected[FrameworkEcho] = true
			}
			if modChiRe.MatchString(modContent) || blockModChiRe.MatchString(modContent) {
				detected[FrameworkChi] = true
			}
			if modFiberRe.MatchString(modContent) || blockModFiberRe.MatchString(modContent) {
				detected[FrameworkFiber] = true
			}
		}
	}

	// 2. Inspect diff for imports
	if diff != "" {
		if importGinRe.MatchString(diff) {
			detected[FrameworkGin] = true
		}
		if importEchoRe.MatchString(diff) {
			detected[FrameworkEcho] = true
		}
		if importChiRe.MatchString(diff) {
			detected[FrameworkChi] = true
		}
		if importFiberRe.MatchString(diff) {
			detected[FrameworkFiber] = true
		}
		if importNetHTTPRe.MatchString(diff) {
			detected[FrameworkNetHTTP] = true
		}
	}

	res := make([]string, 0, len(detected))
	for id := range detected {
		res = append(res, id)
	}
	sort.Strings(res)
	return res
}

// ResolveFrameworkPacks returns the active framework packs, their rules, and corresponding check metadata.
func ResolveFrameworkPacks(repoRoot string, diff string, requested []string) ([]FrameworkPack, []Rule, []CheckResult) {
	allPacks := map[string]FrameworkPack{
		FrameworkGin:     GinPack(repoRoot),
		FrameworkEcho:    EchoPack(repoRoot),
		FrameworkChi:     ChiPack(repoRoot),
		FrameworkFiber:   FiberPack(repoRoot),
		FrameworkNetHTTP: NetHTTPPack(repoRoot),
	}

	enabled := make(map[string]bool)

	// Clean up requested list
	var cleanReq []string
	for _, r := range requested {
		for _, part := range strings.Split(r, ",") {
			part = strings.TrimSpace(strings.ToLower(part))
			if part == "http" {
				part = FrameworkNetHTTP
			}
			if part != "" {
				cleanReq = append(cleanReq, part)
			}
		}
	}

	hasAll := false
	hasNone := false
	hasAuto := false
	for _, req := range cleanReq {
		switch req {
		case "all":
			hasAll = true
		case "none", "off":
			hasNone = true
		case "auto":
			hasAuto = true
		default:
			if _, ok := allPacks[req]; ok {
				enabled[req] = true
			}
		}
	}

	if hasNone {
		return nil, nil, nil
	}

	if hasAll {
		for id := range allPacks {
			enabled[id] = true
		}
	} else if len(enabled) == 0 || hasAuto {
		detected := DetectFrameworks(repoRoot, diff)
		for _, id := range detected {
			enabled[id] = true
		}
	}

	var packs []FrameworkPack
	var rules []Rule
	var checks []CheckResult

	// Keep deterministic order
	order := []string{FrameworkGin, FrameworkEcho, FrameworkChi, FrameworkFiber, FrameworkNetHTTP}
	for _, id := range order {
		if !enabled[id] {
			continue
		}
		pack := allPacks[id]
		packs = append(packs, pack)
		rules = append(rules, pack.Rules...)
		checks = append(checks, CheckResult{
			Name:     "framework:" + pack.ID,
			Category: "framework",
			Status:   "passed",
			Version:  pack.Version,
			Message:  fmt.Sprintf("%s framework pack v%s executed (%d rules)", pack.Name, pack.Version, len(pack.Rules)),
		})
	}

	return packs, rules, checks
}
