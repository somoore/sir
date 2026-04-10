package core

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// ---------------------------------------------------------------------------
// MSTR/1 Encoding Tests
// ---------------------------------------------------------------------------

func TestEncodeMSTR1_FrameStructure(t *testing.T) {
	req := &Request{
		ToolName: "Bash",
		Intent:   Intent{Verb: "execute_dry_run", Target: "ls -la"},
	}
	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	// Header: 4 (magic) + 1 (version) + 4 (length) = 9 bytes minimum
	if len(buf) < 9 {
		t.Fatalf("buffer too short: %d bytes", len(buf))
	}

	// Magic
	if string(buf[0:4]) != "MSTR" {
		t.Errorf("magic = %q, want MSTR", string(buf[0:4]))
	}

	// Version
	if buf[4] != 0x01 {
		t.Errorf("version = %d, want 1", buf[4])
	}

	// Length matches actual payload
	declaredLen := binary.BigEndian.Uint32(buf[5:9])
	actualPayload := buf[9:]
	if int(declaredLen) != len(actualPayload) {
		t.Errorf("declared length %d != actual payload length %d", declaredLen, len(actualPayload))
	}

	// Payload is valid JSON
	var obj map[string]interface{}
	if err := json.Unmarshal(actualPayload, &obj); err != nil {
		t.Errorf("payload is not valid JSON: %v", err)
	}
}

func TestEncodeMSTR1_AllVerbTypes(t *testing.T) {
	for _, verb := range policy.AllVerbs {
		t.Run(string(verb), func(t *testing.T) {
			req := &Request{
				ToolName: "Bash",
				Intent:   Intent{Verb: verb, Target: "test-target"},
			}
			buf, err := encodeMSTR1(req)
			if err != nil {
				t.Fatalf("encodeMSTR1(%s): %v", verb, err)
			}

			payload := decodeMSTR1Payload(t, buf)
			requestObj := payload["request"].(map[string]interface{})
			if requestObj["verb"] != string(verb) {
				t.Errorf("verb = %q, want %q", requestObj["verb"], verb)
			}
		})
	}
}

func TestEncodeMSTR1_AllBooleanFlags(t *testing.T) {
	req := &Request{
		ToolName: "Write",
		Intent: Intent{
			Verb:         "stage_write",
			Target:       ".claude/hooks/hooks.json",
			IsPosture:    true,
			IsSensitive:  true,
			IsTripwire:   true,
			IsDelegation: true,
			Labels: []Label{
				{Sensitivity: "secret", Trust: "trusted", Provenance: "user"},
			},
		},
		Session: SessionInfo{
			SecretSession:         true,
			RecentlyReadUntrusted: true,
			DenyAll:               true,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj := payload["request"].(map[string]interface{})

	boolChecks := map[string]bool{
		"is_posture_file":        true,
		"is_sensitive_path":      true,
		"is_tripwire":            true,
		"is_delegation":          true,
		"session_secret":         true,
		"session_untrusted_read": true,
	}
	for key, want := range boolChecks {
		got, ok := requestObj[key]
		if !ok {
			t.Errorf("missing key %q in request", key)
			continue
		}
		if got != want {
			t.Errorf("request[%q] = %v, want %v", key, got, want)
		}
	}

	sessionObj := payload["session"].(map[string]interface{})
	sessionChecks := map[string]bool{
		"secret_session":          true,
		"recently_read_untrusted": true,
		"deny_all":                true,
	}
	for key, want := range sessionChecks {
		got, ok := sessionObj[key]
		if !ok {
			t.Errorf("missing key %q in session", key)
			continue
		}
		if got != want {
			t.Errorf("session[%q] = %v, want %v", key, got, want)
		}
	}
}

func TestEncodeMSTR1_SerializesSessionScopeAndTurnCounter(t *testing.T) {
	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:   "read_ref",
			Target: ".env",
		},
		Session: SessionInfo{
			SecretSession: true,
			ApprovalScope: "turn",
			TurnCounter:   7,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	sessionObj := payload["session"].(map[string]interface{})
	if got, want := sessionObj["approval_scope"], "turn"; got != want {
		t.Fatalf("approval_scope = %v, want %q", got, want)
	}
	if got, want := int(sessionObj["turn_counter"].(float64)), 7; got != want {
		t.Fatalf("turn_counter = %d, want %d", got, want)
	}
}

func TestEncodeMSTR1_AllFlagsFalse(t *testing.T) {
	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:   "read_ref",
			Target: "src/main.go",
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj := payload["request"].(map[string]interface{})

	falseKeys := []string{
		"is_posture_file", "is_sensitive_path", "is_tripwire",
		"is_delegation", "session_secret", "session_untrusted_read",
	}
	for _, key := range falseKeys {
		if val, ok := requestObj[key]; ok && val == true {
			t.Errorf("request[%q] = true, want false", key)
		}
	}
}

func TestEncodeMSTR1_MultipleLabels(t *testing.T) {
	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:   "read_ref",
			Target: "node_modules/.env",
			Labels: []Label{
				{Sensitivity: "secret", Trust: "trusted", Provenance: "user"},
				{Sensitivity: "none", Trust: "verified_origin", Provenance: "external_package"},
			},
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj := payload["request"].(map[string]interface{})
	labels := requestObj["labels"].([]interface{})
	if len(labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(labels))
	}

	lbl0 := labels[0].(map[string]interface{})
	if lbl0["sensitivity"] != "secret" {
		t.Errorf("label[0].sensitivity = %q, want secret", lbl0["sensitivity"])
	}

	lbl1 := labels[1].(map[string]interface{})
	if lbl1["trust"] != "verified_origin" {
		t.Errorf("label[1].trust = %q, want verified_origin", lbl1["trust"])
	}
	if lbl1["provenance"] != "external_package" {
		t.Errorf("label[1].provenance = %q, want external_package", lbl1["provenance"])
	}
}

func TestEncodeMSTR1_NilLabels(t *testing.T) {
	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:   "read_ref",
			Target: "src/main.go",
			Labels: nil,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj := payload["request"].(map[string]interface{})
	labels := requestObj["labels"].([]interface{})
	if len(labels) != 0 {
		t.Errorf("expected empty labels for nil input, got %d", len(labels))
	}
}

func TestEncodeMSTR1_WithLeaseJSON(t *testing.T) {
	lease := map[string]interface{}{
		"approved_hosts":   []string{"api.example.com"},
		"approved_remotes": []string{"origin"},
		"sensitive_paths":  []string{".env", "*.pem"},
	}
	leaseJSON, _ := json.Marshal(lease)

	req := &Request{
		ToolName:  "Bash",
		LeaseJSON: leaseJSON,
		Intent:    Intent{Verb: "net_allowlisted", Target: "api.example.com"},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)

	// Verify lease is included in the payload
	leaseObj, ok := payload["lease"]
	if !ok {
		t.Fatal("lease missing from payload when LeaseJSON provided")
	}
	leaseMap := leaseObj.(map[string]interface{})
	hosts := leaseMap["approved_hosts"].([]interface{})
	if len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Errorf("lease.approved_hosts = %v, want [api.example.com]", hosts)
	}
}

func TestEncodeMSTR1_WithoutLeaseJSON(t *testing.T) {
	req := &Request{
		ToolName: "Read",
		Intent:   Intent{Verb: "read_ref", Target: "file.go"},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	if _, ok := payload["lease"]; ok {
		t.Error("lease should not be present when LeaseJSON is empty")
	}
}

func TestEncodeMSTR1_InvalidLeaseJSON(t *testing.T) {
	req := &Request{
		ToolName:  "Bash",
		LeaseJSON: []byte("not valid json{{{"),
		Intent:    Intent{Verb: "execute_dry_run", Target: "ls"},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v (should succeed, just skip lease)", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	// Invalid lease JSON should be silently dropped
	if _, ok := payload["lease"]; ok {
		t.Error("invalid lease JSON should not be included in payload")
	}
}

// ---------------------------------------------------------------------------
// MSTR/1 Decoding Tests
// ---------------------------------------------------------------------------

func buildMSTR1Response(t *testing.T, jsonPayload string) []byte {
	t.Helper()
	payloadBytes := []byte(jsonPayload)
	var buf []byte
	buf = append(buf, "MSTR"...)
	buf = append(buf, 0x01)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(payloadBytes)))
	buf = append(buf, lenBytes...)
	buf = append(buf, payloadBytes...)
	return buf
}

func TestDecodeMSTR1Response_AllDecisionTypes(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		decision policy.Verdict
		reason   string
		risk     string
	}{
		{
			name:     "allow",
			json:     `{"verdict":"allow","reason":"within lease boundary"}`,
			decision: "allow",
			reason:   "within lease boundary",
		},
		{
			name:     "deny",
			json:     `{"verdict":"deny","reason":"session carries secret-labeled data, sink is untrusted"}`,
			decision: policy.VerdictDeny,
			reason:   "session carries secret-labeled data, sink is untrusted",
		},
		{
			name:     "ask",
			json:     `{"verdict":"ask","reason":"write to posture file: hooks.json"}`,
			decision: policy.VerdictAsk,
			reason:   "write to posture file: hooks.json",
		},
		{
			name:     "deny with risk tier",
			json:     `{"verdict":"deny","reason":"blocked","risk_tier":"R4"}`,
			decision: "deny",
			reason:   "blocked",
			risk:     "R4",
		},
		{
			name:     "ask with risk tier",
			json:     `{"verdict":"ask","reason":"needs approval","risk_tier":"R3"}`,
			decision: "ask",
			reason:   "needs approval",
			risk:     "R3",
		},
		{
			name:     "allow with R0 risk",
			json:     `{"verdict":"allow","reason":"safe","risk_tier":"R0"}`,
			decision: policy.VerdictAllow,
			reason:   "safe",
			risk:     "R0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := buildMSTR1Response(t, tc.json)
			resp, err := decodeMSTR1Response(buf)
			if err != nil {
				t.Fatalf("decodeMSTR1Response: %v", err)
			}
			if resp.Decision != tc.decision {
				t.Errorf("decision = %q, want %q", resp.Decision, tc.decision)
			}
			if resp.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", resp.Reason, tc.reason)
			}
			if resp.Risk != tc.risk {
				t.Errorf("risk = %q, want %q", resp.Risk, tc.risk)
			}
		})
	}
}

func TestDecodeMSTR1Response_AllRiskTiers(t *testing.T) {
	tiers := []string{"R0", "R1", "R2", "R3", "R4"}
	for _, tier := range tiers {
		t.Run(tier, func(t *testing.T) {
			payload := `{"verdict":"ask","reason":"test","risk_tier":"` + tier + `"}`
			buf := buildMSTR1Response(t, payload)
			resp, err := decodeMSTR1Response(buf)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Risk != tier {
				t.Errorf("risk = %q, want %q", resp.Risk, tier)
			}
		})
	}
}

func TestDecodeMSTR1Response_VersionMismatch(t *testing.T) {
	payload := []byte(`{"verdict":"allow","reason":"ok"}`)
	var buf []byte
	buf = append(buf, "MSTR"...)
	buf = append(buf, 0x02) // version 2, not supported
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(payload)))
	buf = append(buf, lenBytes...)
	buf = append(buf, payload...)

	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Fatal("expected error for version mismatch")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error should mention version: %v", err)
	}
}

func TestDecodeMSTR1Response_LengthMismatch(t *testing.T) {
	// Declare length larger than actual payload
	payload := []byte(`{"verdict":"allow"}`)
	var buf []byte
	buf = append(buf, "MSTR"...)
	buf = append(buf, 0x01)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(payload)+100)) // declare 100 extra bytes
	buf = append(buf, lenBytes...)
	buf = append(buf, payload...)

	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Fatal("expected error for length mismatch")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Errorf("error should mention length: %v", err)
	}
}

func TestDecodeMSTR1Response_MalformedJSON(t *testing.T) {
	malformedJSON := `{"verdict":"allow", broken`
	buf := buildMSTR1Response(t, malformedJSON)

	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDecodeMSTR1Response_EmptyPayload(t *testing.T) {
	// Valid frame with zero-length payload (empty JSON)
	var buf []byte
	buf = append(buf, "MSTR"...)
	buf = append(buf, 0x01)
	buf = append(buf, 0, 0, 0, 0) // length = 0

	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestDecodeMSTR1Response_ExactlyNineBytes(t *testing.T) {
	// Just the header, no payload (length says 0)
	buf := []byte("MSTR\x01\x00\x00\x00\x00")
	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Fatal("expected error for zero-length payload (can't unmarshal)")
	}
}

func TestDecodeMSTR1Response_ExtraTrailingBytes(t *testing.T) {
	// Valid response followed by garbage — should still decode correctly
	payload := `{"verdict":"allow","reason":"ok"}`
	buf := buildMSTR1Response(t, payload)
	buf = append(buf, []byte("GARBAGE TRAILING DATA")...)

	resp, err := decodeMSTR1Response(buf)
	if err != nil {
		t.Fatalf("should succeed even with trailing data: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
}

// ---------------------------------------------------------------------------
// Round-Trip Encoding Tests
// ---------------------------------------------------------------------------

func TestRoundTrip_EncodeDecodeFields(t *testing.T) {
	req := &Request{
		ToolName: "Bash",
		Intent: Intent{
			Verb:        "net_external",
			Target:      "https://evil.com/exfil",
			IsPosture:   false,
			IsSensitive: false,
			IsTripwire:  false,
			Labels: []Label{
				{Sensitivity: "none", Trust: "trusted", Provenance: "user"},
			},
		},
		Session: SessionInfo{
			SecretSession:         true,
			RecentlyReadUntrusted: false,
			DenyAll:               false,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Extract payload JSON
	payloadJSON := buf[9:]
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	requestObj := payload["request"].(map[string]interface{})
	if requestObj["tool_name"] != "Bash" {
		t.Errorf("tool_name = %v", requestObj["tool_name"])
	}
	if requestObj["verb"] != "net_external" {
		t.Errorf("verb = %v", requestObj["verb"])
	}
	if requestObj["target"] != "https://evil.com/exfil" {
		t.Errorf("target = %v", requestObj["target"])
	}
}

func TestRoundTrip_EdgeCase_EmptyStrings(t *testing.T) {
	req := &Request{
		ToolName: "",
		Intent: Intent{
			Verb:   "",
			Target: "",
			Labels: []Label{},
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj := payload["request"].(map[string]interface{})
	if requestObj["tool_name"] != "" {
		t.Errorf("tool_name = %q, want empty", requestObj["tool_name"])
	}
	if requestObj["verb"] != "" {
		t.Errorf("verb = %q, want empty", requestObj["verb"])
	}
	if requestObj["target"] != "" {
		t.Errorf("target = %q, want empty", requestObj["target"])
	}
}

func TestRoundTrip_EdgeCase_VeryLongTarget(t *testing.T) {
	longPath := strings.Repeat("a/", 2000) + ".env"
	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:   "read_ref",
			Target: longPath,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj := payload["request"].(map[string]interface{})
	if requestObj["target"] != longPath {
		t.Error("long target was truncated or corrupted")
	}
}

func TestRoundTrip_EdgeCase_SpecialCharactersInPath(t *testing.T) {
	targets := []string{
		`path with spaces/.env`,
		`path/with "quotes"/.env`,
		"path/with\nnewline/.env",
		"path/with\ttab/.env",
		`path/with/émojis/🔑/.env`,
		`path/with\backslash/.env`,
		`../../.env`,
		`/absolute/path/to/.env`,
	}

	for _, target := range targets {
		t.Run(target[:min(len(target), 30)], func(t *testing.T) {
			req := &Request{
				ToolName: "Read",
				Intent:   Intent{Verb: "read_ref", Target: target},
			}

			buf, err := encodeMSTR1(req)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			payload := decodeMSTR1Payload(t, buf)
			requestObj := payload["request"].(map[string]interface{})
			if requestObj["target"] != target {
				t.Errorf("target = %q, want %q", requestObj["target"], target)
			}
		})
	}
}

func TestRoundTrip_EdgeCase_UnicodeInReason(t *testing.T) {
	payload := `{"verdict":"deny","reason":"blocked: path contains émojis 🔑"}`
	buf := buildMSTR1Response(t, payload)
	resp, err := decodeMSTR1Response(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Reason != "blocked: path contains émojis 🔑" {
		t.Errorf("reason lost unicode characters: %q", resp.Reason)
	}
}

// ---------------------------------------------------------------------------
