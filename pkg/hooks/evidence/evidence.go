package evidence

import (
	"encoding/json"

	"github.com/somoore/sir/pkg/ledger"
)

func MarshalMCP(toolInput map[string]interface{}) string {
	if len(toolInput) == 0 {
		return ""
	}
	redacted := ledger.RedactMapValues(toolInput)
	data, err := json.Marshal(redacted)
	if err != nil {
		return ""
	}
	return ledger.TruncateToWordBoundary(string(data), 2048)
}

func RedactToolOutput(output string) string {
	if output == "" {
		return ""
	}
	return ledger.RedactContent(output, 1024)
}
