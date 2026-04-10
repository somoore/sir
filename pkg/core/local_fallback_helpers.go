package core

import "github.com/somoore/sir/pkg/policy"

func isWriteVerb(verb policy.Verb) bool {
	return verb == policy.VerbStageWrite
}

func hasDerivedSecret(labels []Label) bool {
	for _, label := range labels {
		if label.Sensitivity == "secret" {
			return true
		}
	}
	return false
}

func deniesFlowToVerb(labels []Label, verb policy.Verb) bool {
	if len(labels) == 0 {
		return false
	}
	sinkTrust := "trusted"
	switch verb {
	case policy.VerbPushRemote, policy.VerbNetExternal, policy.VerbDnsLookup:
		sinkTrust = "untrusted"
	case policy.VerbPushOrigin, policy.VerbNetAllowlisted:
		sinkTrust = "verified_internal"
	}
	combinedSensitivity := "public"
	combinedTrust := "trusted"
	for _, label := range labels {
		if label.Sensitivity == "secret" {
			combinedSensitivity = "secret"
		} else if combinedSensitivity != "secret" && label.Sensitivity == "restricted" {
			combinedSensitivity = "restricted"
		}
		if label.Trust == "untrusted" {
			combinedTrust = "untrusted"
		} else if combinedTrust == "trusted" && label.Trust == "verified_origin" {
			combinedTrust = "verified_origin"
		}
	}
	if (combinedSensitivity == "secret" || combinedSensitivity == "restricted") && sinkTrust == "untrusted" {
		return true
	}
	return combinedTrust == "untrusted" && sinkTrust == "untrusted"
}
