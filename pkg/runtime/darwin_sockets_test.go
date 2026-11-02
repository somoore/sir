package runtime

import (
	"strings"
	"testing"
)

func TestDarwinHostControlSocketsAreDenied(t *testing.T) {
	profile, err := BuildDarwinProfile(t.TempDir(), Options{})
	if err != nil {
		t.Fatalf("BuildDarwinProfile: %v", err)
	}
	for _, want := range []string{
		"/var/run/docker.sock",
		"/run/containerd/containerd.sock",
		".gnupg/S.gpg-agent",
	} {
		found := false
		for _, line := range strings.Split(profile, "\n") {
			if strings.Contains(line, `(deny network-outbound (remote unix-socket (path-literal "`) &&
				strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("profile must deny host-control socket %q; profile:\n%s", want, profile)
		}
	}
	if strings.Index(profile, `(allow network-outbound (remote unix-socket))`) >
		strings.Index(profile, `(deny network-outbound (remote unix-socket (path-literal "/var/run/docker.sock")))`) {
		t.Error("host-control socket denies must come after the blanket unix-socket allow (last match wins)")
	}
}
