package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/repair"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// LSPMessage represents a standard JSON-RPC 2.0 message used by the Language Server Protocol.
type LSPMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *LSPError       `json:"error,omitempty"`
}

type LSPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type LSPPosition struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type LSPRange struct {
	Start LSPPosition `json:"start"`
	End   LSPPosition `json:"end"`
}

type LSPDiagnostic struct {
	Range    LSPRange `json:"range"`
	Severity int      `json:"severity"` // 1: Error, 2: Warning, 3: Information, 4: Hint
	Code     string   `json:"code"`
	Source   string   `json:"source"`
	Message  string   `json:"message"`
}

type LSPTextEdit struct {
	Range   LSPRange `json:"range"`
	NewText string   `json:"newText"`
}

type LSPWorkspaceEdit struct {
	Changes map[string][]LSPTextEdit `json:"changes"`
}

type LSPCodeAction struct {
	Title string            `json:"title"`
	Kind  string            `json:"kind"`
	Edit  *LSPWorkspaceEdit `json:"edit,omitempty"`
}

// LSPServer runs a deterministic Language Server Protocol daemon over standard I/O.
type LSPServer struct {
	in         io.Reader
	out        io.Writer
	repoRoot   string
	documents  map[string]string // uri -> content
	mu         sync.Mutex
	lastReport map[string][]review.Finding // uri -> findings
}

func NewLSPServer(in io.Reader, out io.Writer, repoRoot string) *LSPServer {
	return &LSPServer{
		in:         in,
		out:        out,
		repoRoot:   repoRoot,
		documents:  make(map[string]string),
		lastReport: make(map[string][]review.Finding),
	}
}

// Serve reads JSON-RPC 2.0 messages from in and writes responses to out.
func (s *LSPServer) Serve() error {
	reader := bufio.NewReader(s.in)

	for {
		msg, err := readLSPMessage(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		if err := s.handleMessage(msg); err != nil {
			return err
		}
	}
}

func readLSPMessage(reader *bufio.Reader) (*LSPMessage, error) {
	contentLength := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}

		if strings.HasPrefix(line, "Content-Length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				contentLength, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		}
	}

	if contentLength == 0 {
		return nil, fmt.Errorf("missing or zero Content-Length header")
	}

	payload := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}

	var msg LSPMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func (s *LSPServer) send(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := io.WriteString(s.out, header); err != nil {
		return err
	}
	_, err = s.out.Write(data)
	return err
}

func (s *LSPServer) handleMessage(msg *LSPMessage) error {
	switch msg.Method {
	case "initialize":
		res := map[string]interface{}{
			"capabilities": map[string]interface{}{
				"textDocumentSync":   1, // Full
				"codeActionProvider": true,
			},
			"serverInfo": map[string]string{
				"name":    "m3tal-review-lsp",
				"version": version,
			},
		}
		return s.send(LSPMessage{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  res,
		})

	case "initialized":
		return nil

	case "shutdown":
		return s.send(LSPMessage{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  map[string]interface{}{},
		})

	case "exit":
		os.Exit(0)
		return nil

	case "textDocument/didOpen":
		var params struct {
			TextDocument struct {
				URI  string `json:"uri"`
				Text string `json:"text"`
			} `json:"textDocument"`
		}
		if err := json.Unmarshal(msg.Params, &params); err == nil {
			s.mu.Lock()
			s.documents[params.TextDocument.URI] = params.TextDocument.Text
			s.mu.Unlock()
			s.analyzeDocument(params.TextDocument.URI, params.TextDocument.Text)
		}
		return nil

	case "textDocument/didChange":
		var params struct {
			TextDocument struct {
				URI string `json:"uri"`
			} `json:"textDocument"`
			ContentChanges []struct {
				Text string `json:"text"`
			} `json:"contentChanges"`
		}
		if err := json.Unmarshal(msg.Params, &params); err == nil && len(params.ContentChanges) > 0 {
			text := params.ContentChanges[0].Text
			s.mu.Lock()
			s.documents[params.TextDocument.URI] = text
			s.mu.Unlock()
			s.analyzeDocument(params.TextDocument.URI, text)
		}
		return nil

	case "textDocument/didSave":
		var params struct {
			TextDocument struct {
				URI string `json:"uri"`
			} `json:"textDocument"`
		}
		if err := json.Unmarshal(msg.Params, &params); err == nil {
			s.mu.Lock()
			text := s.documents[params.TextDocument.URI]
			s.mu.Unlock()
			if text != "" {
				s.analyzeDocument(params.TextDocument.URI, text)
			}
		}
		return nil

	case "textDocument/codeAction":
		var params struct {
			TextDocument struct {
				URI string `json:"uri"`
			} `json:"textDocument"`
			Context struct {
				Diagnostics []LSPDiagnostic `json:"diagnostics"`
			} `json:"context"`
		}
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return nil
		}

		actions := s.generateCodeActions(params.TextDocument.URI, params.Context.Diagnostics)
		return s.send(LSPMessage{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Result:  actions,
		})
	}

	return nil
}

func (s *LSPServer) analyzeDocument(uri, content string) {
	relPath := uriToRelativePath(uri, s.repoRoot)
	diff := syntheticFileDiff(relPath, content)

	rules := defaultRules(s.repoRoot)
	engine := review.NewEngine(rules...)
	findings := engine.Run(diff)

	s.mu.Lock()
	s.lastReport[uri] = findings
	s.mu.Unlock()

	var diagnostics []LSPDiagnostic
	for _, f := range findings {
		line := f.Line - 1
		if line < 0 {
			line = 0
		}

		sev := 2 // Warning
		switch strings.ToLower(f.Severity) {
		case "critical", "high":
			sev = 1 // Error
		case "medium":
			sev = 2 // Warning
		case "low":
			sev = 3 // Information
		}

		diagnostics = append(diagnostics, LSPDiagnostic{
			Range: LSPRange{
				Start: LSPPosition{Line: line, Character: 0},
				End:   LSPPosition{Line: line, Character: 999},
			},
			Severity: sev,
			Code:     f.Rule,
			Source:   "m3tal-review",
			Message:  f.Message,
		})
	}

	s.send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "textDocument/publishDiagnostics",
		"params": map[string]interface{}{
			"uri":         uri,
			"diagnostics": diagnostics,
		},
	})
}

func (s *LSPServer) generateCodeActions(uri string, diagnostics []LSPDiagnostic) []LSPCodeAction {
	s.mu.Lock()
	content := s.documents[uri]
	findings := s.lastReport[uri]
	s.mu.Unlock()

	if content == "" || len(findings) == 0 {
		return nil
	}

	var actions []LSPCodeAction
	for _, diag := range diagnostics {
		for _, f := range findings {
			if f.Rule == diag.Code && (f.Line-1 == diag.Range.Start.Line || diag.Range.Start.Line == 0) {
				fixer := repair.FindFixerForFinding(f)
				if fixer != nil {
					prop, err := fixer.GenerateProposal(context.Background(), s.repoRoot, f, []byte(content))
					if err == nil && prop != nil {
						lineCount := strings.Count(content, "\n") + 1
						actions = append(actions, LSPCodeAction{
							Title: fmt.Sprintf("Fix with %s: %s", fixer.Name(), prop.Explanation),
							Kind:  "quickfix",
							Edit: &LSPWorkspaceEdit{
								Changes: map[string][]LSPTextEdit{
									uri: {
										{
											Range: LSPRange{
												Start: LSPPosition{Line: 0, Character: 0},
												End:   LSPPosition{Line: lineCount, Character: 0},
											},
											NewText: prop.ProposedContent,
										},
									},
								},
							},
						})
					}
				}
			}
		}
	}

	return actions
}

func uriToRelativePath(uri, root string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Path == "" {
		return uri
	}
	path := u.Path
	if root != "" {
		rel, err := filepath.Rel(root, path)
		if err == nil {
			return rel
		}
	}
	return path
}

func syntheticFileDiff(relPath, content string) string {
	var b bytes.Buffer
	b.WriteString(fmt.Sprintf("diff --git a/%s b/%s\n", relPath, relPath))
	b.WriteString(fmt.Sprintf("--- a/%s\n", relPath))
	b.WriteString(fmt.Sprintf("+++ b/%s\n", relPath))
	lineCount := strings.Count(content, "\n") + 1
	b.WriteString(fmt.Sprintf("@@ -0,0 +1,%d @@\n", lineCount))
	for _, line := range strings.Split(content, "\n") {
		b.WriteString("+" + line + "\n")
	}
	return b.String()
}
