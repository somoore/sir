package classify

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

func TestContainsSirSelfCommand(t *testing.T) {
	cmd := `printf "safe" && /usr/local/bin/sir trust mcp-server`
	if !ContainsSirSelfCommand(cmd) {
		t.Fatalf("ContainsSirSelfCommand(%q) = false, want true", cmd)
	}
}

func TestDetectSensitiveFileRead(t *testing.T) {
	l := &lease.Lease{SensitivePaths: []string{".env"}}

	target, ok := DetectSensitiveFileRead("env FOO=bar /bin/cat .env", l)
	if !ok {
		t.Fatal("expected sensitive read to be detected")
	}
	if target != ".env" {
		t.Fatalf("target = %q, want .env", target)
	}
}

func TestIsPostureDeleteOrLink(t *testing.T) {
	l := &lease.Lease{PostureFiles: []string{"AGENTS.md"}}

	if !IsPostureDeleteOrLink("ln -sf ./tmp-link AGENTS.md", l) {
		t.Fatal("expected posture link command to be detected")
	}
}

func TestVerbRiskOrdering(t *testing.T) {
	if got, wantMin := VerbRisk(policy.VerbSirSelf), VerbRisk(policy.VerbPushRemote); got <= wantMin {
		t.Fatalf("VerbRisk(VerbSirSelf) = %d, want > %d", got, wantMin)
	}
	if got, want := VerbRisk(policy.VerbRunTests), 5; got != want {
		t.Fatalf("VerbRisk(VerbRunTests) = %d, want %d", got, want)
	}
}
