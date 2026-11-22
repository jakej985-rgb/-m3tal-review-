package cli

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestLSPServer_InitializeAndDiagnostics(t *testing.T) {
	var in bytes.Buffer
	var out bytes.Buffer

	server := NewLSPServer(&in, &out, "")

	// 1. Send initialize request
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	in.WriteString(formatLSPMessage(initReq))

	// 2. Send textDocument/didOpen with a Dart file having an inoperable Semantics button
	badDart := `
class MyWidget extends StatelessWidget {
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      excludeSemantics: true,
      child: GestureDetector(
        onTap: () {},
        child: Text("Click"),
      ),
    );
  }
}
`
	openParams, _ := json.Marshal(map[string]interface{}{
		"textDocument": map[string]interface{}{
			"uri":  "file:///workspace/lib/button.dart",
			"text": badDart,
		},
	})
	openNotif := `{"jsonrpc":"2.0","method":"textDocument/didOpen","params":` + string(openParams) + `}`
	in.WriteString(formatLSPMessage(openNotif))

	// Run serve in a goroutine until EOF
	done := make(chan error, 1)
	go func() {
		done <- server.Serve()
	}()

	err := <-done
	if err != nil {
		t.Fatalf("server.Serve returned error: %v", err)
	}

	outStr := out.String()
	if !strings.Contains(outStr, `"capabilities"`) {
		t.Errorf("expected initialize response with capabilities, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, `"textDocument/publishDiagnostics"`) {
		t.Errorf("expected publishDiagnostics notification, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, `"flutter-semantics-action"`) {
		t.Errorf("expected diagnostic for flutter-semantics-action, got:\n%s", outStr)
	}
}

func formatLSPMessage(body string) string {
	return "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}
