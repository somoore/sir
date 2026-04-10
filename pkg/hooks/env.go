package hooks

import "os"

func EnvLogToolContent() bool {
	return os.Getenv("SIR_LOG_TOOL_CONTENT") == "1"
}
