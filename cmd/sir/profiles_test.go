package main

import "testing"

func TestLeaseForProfile(t *testing.T) {
	cases := []struct {
		profile        string
		wantDenyRaw    bool
		wantDelegation bool
		wantAutoLease  bool
		wantErr        bool
	}{
		{"personal", false, true, true, false},
		{"default", false, true, true, false},
		{"standard", false, true, true, false},
		{"team", true, true, true, false},
		{"strict", true, false, false, false},
		{"bogus", false, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.profile, func(t *testing.T) {
			l, err := leaseForProfile(c.profile)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for profile %q", c.profile)
				}
				return
			}
			if err != nil {
				t.Fatalf("leaseForProfile(%q): %v", c.profile, err)
			}
			if l.DenyRawSecretReads != c.wantDenyRaw {
				t.Errorf("DenyRawSecretReads = %v, want %v", l.DenyRawSecretReads, c.wantDenyRaw)
			}
			if l.AllowDelegation != c.wantDelegation {
				t.Errorf("AllowDelegation = %v, want %v", l.AllowDelegation, c.wantDelegation)
			}
			if l.AutoLeaseApprovedHosts != c.wantAutoLease {
				t.Errorf("AutoLeaseApprovedHosts = %v, want %v", l.AutoLeaseApprovedHosts, c.wantAutoLease)
			}
		})
	}
}
