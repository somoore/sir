package agent

import (
	"fmt"
	"strings"
)

// ValidateSupportContract ensures the hand-maintained support metadata on an
// adapter spec still matches the capability model and registered hooks.
func ValidateSupportContract(spec *AgentSpec) error {
	if spec == nil {
		return nil
	}
	problems := make([]string, 0, 4)

	expectedSIREvents := derivedSupportedSIREvents(spec)
	if !equalStringSlices(spec.SupportedSIREvents, expectedSIREvents) {
		problems = append(problems, fmt.Sprintf("supported sir events drift: got %v want %v", spec.SupportedSIREvents, expectedSIREvents))
	}

	expectedWireEvents := derivedSupportedWireEvents(spec, expectedSIREvents)
	if !equalStringSlices(spec.SupportedWireEvents, expectedWireEvents) {
		problems = append(problems, fmt.Sprintf("supported wire events drift: got %v want %v", spec.SupportedWireEvents, expectedWireEvents))
	}

	if spec.Capabilities.SupportTier != SupportTierReference && spec.MinVersion == "" {
		problems = append(problems, "support tier requires a minimum version for generated prose")
	}

	if spec.Capabilities.ToolCoverage == ToolCoverageBashOnly || spec.RequiredFeatureFlag != "" {
		if spec.RequiredFeatureFlag == "" {
			problems = append(problems, "feature-gated support requires a feature flag for generated prose")
		}
		if spec.FeatureFlagEnableCommand == "" {
			problems = append(problems, "feature-gated support requires a feature-flag enable command for generated prose")
		}
	}

	for _, registration := range spec.HookRegistrations {
		if !spec.Capabilities.SupportsEvent(registration.Event) {
			problems = append(problems, fmt.Sprintf("hook registration %q is not declared supported in capabilities", registration.Event))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf(strings.Join(problems, "; "))
	}
	return nil
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
