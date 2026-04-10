package core

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// ---------------------------------------------------------------------------
// isWriteVerb helper
// ---------------------------------------------------------------------------

func TestIsWriteVerb(t *testing.T) {
	if !isWriteVerb(policy.VerbStageWrite) {
		t.Error("stage_write should be a write verb")
	}
	nonWriteVerbs := []policy.Verb{
		policy.VerbReadRef,
		policy.VerbExecuteDryRun,
		policy.VerbNetExternal,
		policy.VerbCommit,
		policy.VerbListFiles,
		policy.Verb(""),
	}
	for _, v := range nonWriteVerbs {
		if isWriteVerb(v) {
			t.Errorf("%q should not be a write verb", v)
		}
	}
}

// ---------------------------------------------------------------------------
// Encoding: Session state is duplicated in both request and session fields
// ---------------------------------------------------------------------------

func TestEncodeMSTR1_SessionDuplication(t *testing.T) {
	// The MSTR/1 protocol sends session info in BOTH request.session_secret/session_untrusted_read
	// AND in the top-level session object. Verify both are consistent.
	req := &Request{
		ToolName: "Bash",
		Intent:   Intent{Verb: "net_external", Target: "example.com"},
		Session: SessionInfo{
			SecretSession:         true,
			RecentlyReadUntrusted: true,
			DenyAll:               false,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)

	// Check request-level session fields
	requestObj := payload["request"].(map[string]interface{})
	if requestObj["session_secret"] != true {
		t.Error("request.session_secret should be true")
	}
	if requestObj["session_untrusted_read"] != true {
		t.Error("request.session_untrusted_read should be true")
	}

	// Check top-level session object
	sessionObj := payload["session"].(map[string]interface{})
	if sessionObj["secret_session"] != true {
		t.Error("session.secret_session should be true")
	}
	if sessionObj["recently_read_untrusted"] != true {
		t.Error("session.recently_read_untrusted should be true")
	}
	if sessionObj["deny_all"] != false {
		t.Error("session.deny_all should be false")
	}
}

// ---------------------------------------------------------------------------
// Encoding: Payload length correctness for various sizes
// ---------------------------------------------------------------------------

func TestEncodeMSTR1_PayloadLengthAccuracy(t *testing.T) {
	sizes := []int{0, 1, 5, 100}
	for _, labelCount := range sizes {
		t.Run("labels="+strings.Repeat("x", labelCount), func(t *testing.T) {
			labels := make([]Label, labelCount)
			for i := range labels {
				labels[i] = Label{
					Sensitivity: "none",
					Trust:       "trusted",
					Provenance:  "user",
				}
			}

			req := &Request{
				ToolName: "Read",
				Intent: Intent{
					Verb:   "read_ref",
					Target: "file.go",
					Labels: labels,
				},
			}

			buf, err := encodeMSTR1(req)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			declaredLen := binary.BigEndian.Uint32(buf[5:9])
			actualLen := len(buf) - 9
			if int(declaredLen) != actualLen {
				t.Errorf("declared %d != actual %d", declaredLen, actualLen)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
