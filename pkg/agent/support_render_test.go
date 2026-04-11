package agent

import (
	"strings"
	"testing"
)

func TestSupportNarrativeBlocksUseManifestData(t *testing.T) {
	readme := RenderReadmeSupportBlock()
	faq := RenderFAQSupportBlock()
	scope := RenderThreatModelScopeBlock()

	for _, manifest := range orderedPublicSupportManifests() {
		if !strings.Contains(readme, manifest.Name) {
			t.Fatalf("README support block missing manifest name %q", manifest.Name)
		}
		if manifest.MinimumVersion != "" && !strings.Contains(readme, manifest.MinimumVersion) {
			t.Fatalf("README support block missing minimum version %q", manifest.MinimumVersion)
		}
		if !strings.Contains(faq, manifest.Name) {
			t.Fatalf("FAQ support block missing manifest name %q", manifest.Name)
		}
		if manifest.MinimumVersion != "" && !strings.Contains(faq, manifest.MinimumVersion) {
			t.Fatalf("FAQ support block missing minimum version %q", manifest.MinimumVersion)
		}
	}

	claude, _ := SupportManifestForID(Claude)
	gemini, _ := SupportManifestForID(Gemini)
	codex, _ := SupportManifestForID(Codex)

	if !strings.Contains(scope, claude.Name) {
		t.Fatalf("threat-model scope block missing %q", claude.Name)
	}
	if !strings.Contains(scope, gemini.Name) {
		t.Fatalf("threat-model scope block missing %q", gemini.Name)
	}
	if !strings.Contains(scope, codex.Name) {
		t.Fatalf("threat-model scope block missing %q", codex.Name)
	}
	if !strings.Contains(scope, missingLifecycleMitigations(gemini)) {
		t.Fatalf("threat-model scope block missing Gemini mitigation summary %q", missingLifecycleMitigations(gemini))
	}
	if !strings.Contains(scope, supportThreatModelDocPath(gemini)) {
		t.Fatalf("threat-model scope block missing Gemini docs path %q", supportThreatModelDocPath(gemini))
	}
	if !strings.Contains(scope, supportThreatModelDocPath(codex)) {
		t.Fatalf("threat-model scope block missing Codex docs path %q", supportThreatModelDocPath(codex))
	}
}

func TestSupportNarrativeBlocksUseDocPathsAndStayWellFormedWithoutOne(t *testing.T) {
	for _, manifest := range orderedPublicSupportManifests() {
		if manifest.SupportTier != SupportTierReference {
			path := supportDocPath(manifest)
			if got := renderFAQLine(manifest); !strings.Contains(got, path) {
				t.Fatalf("FAQ line for %s missing manifest doc path %q: %s", manifest.Name, path, got)
			}
		}
	}

	custom := SupportManifest{
		ID:             AgentID("future"),
		Name:           "Future CLI",
		MinimumVersion: "9.9.9",
		SupportTier:    SupportTierNearParity,
		HookEventCount: 7,
	}

	readmeLine := custom.supportOverviewLine()
	if strings.Contains(readmeLine, "[]()") || strings.Contains(readmeLine, "See []") {
		t.Fatalf("README overview line used broken markdown without a doc path: %s", readmeLine)
	}

	faqLine := custom.faqLine()
	if strings.Contains(faqLine, "[]()") || strings.Contains(faqLine, "See []") {
		t.Fatalf("FAQ line used broken markdown without a doc path: %s", faqLine)
	}
}

func TestValidateSupportContractRequiresGeneratedProseInputs(t *testing.T) {
	limited := codexSpec
	limited.MinVersion = ""
	limited.RequiredFeatureFlag = ""
	limited.FeatureFlagEnableCommand = ""
	if err := ValidateSupportContract(&limited); err == nil {
		t.Fatal("ValidateSupportContract should reject limited support without prose inputs")
	}

	nearParity := geminiSpec
	nearParity.MinVersion = ""
	if err := ValidateSupportContract(&nearParity); err == nil {
		t.Fatal("ValidateSupportContract should reject non-reference support without a minimum version")
	}
}
