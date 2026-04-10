package core

import "github.com/somoore/sir/pkg/policy"

// Request is the evaluation request sent to mister-core via MSTR/1.
type Request struct {
	Version   uint8       `json:"-"`
	LeaseJSON []byte      `json:"-"`
	ToolName  string      `json:"tool_name"`
	Intent    Intent      `json:"intent"`
	Session   SessionInfo `json:"session"`
}

// Intent describes the classified intent of a tool call.
type Intent struct {
	Verb          policy.Verb `json:"verb"`
	Target        string      `json:"target"`
	Labels        []Label     `json:"labels"`
	DerivedLabels []Label     `json:"derived_labels,omitempty"`
	IsPosture     bool        `json:"is_posture"`
	IsSensitive   bool        `json:"is_sensitive"`
	IsTripwire    bool        `json:"is_tripwire"`
	IsDelegation  bool        `json:"is_delegation"`
}

// Label represents an IFC label.
type Label struct {
	Sensitivity string `json:"sensitivity"`
	Trust       string `json:"trust"`
	Provenance  string `json:"provenance"`
}

// SessionInfo is the session context sent to mister-core.
type SessionInfo struct {
	SecretSession         bool   `json:"secret_session"`
	RecentlyReadUntrusted bool   `json:"recently_read_untrusted"`
	DenyAll               bool   `json:"deny_all"`
	ApprovalScope         string `json:"approval_scope,omitempty"`
	TurnCounter           int    `json:"turn_counter,omitempty"`
}

// Response is the verdict from mister-core.
type Response struct {
	Decision policy.Verdict `json:"verdict"`
	Reason   string         `json:"reason"`
	Risk     string         `json:"risk_tier,omitempty"`
}

// CoreBinaryPath is the path to the mister-core binary.
// It can be overridden for testing.
var CoreBinaryPath = "mister-core"
