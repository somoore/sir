package runtime

import (
	"fmt"
	"os/exec"
)

func ensureLinuxIPv6Filtering(resolved []linuxResolvedDestination) error {
	_, ipv6 := splitLinuxResolvedDestinations(resolved)
	if len(ipv6) == 0 {
		return nil
	}
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return fmt.Errorf("linux exact-destination containment requires `ip6tables` on PATH when allowlisted hosts resolve to IPv6")
	}
	return nil
}
