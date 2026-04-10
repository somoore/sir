package core

import (
	"fmt"

	"github.com/somoore/sir/pkg/policy"
)

func localEvaluateNetwork(req *Request, effectiveLabels []Label) *Response {
	switch req.Intent.Verb {
	case policy.VerbNetExternal:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		if req.Session.SecretSession {
			return &Response{Decision: policy.VerdictDeny, Reason: "This session may contain credentials. Network requests to external hosts are blocked."}
		}
		return &Response{Decision: policy.VerdictDeny, Reason: "Network requests to external hosts are blocked by default."}
	case policy.VerbPushRemote:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		if req.Session.SecretSession {
			return &Response{Decision: policy.VerdictDeny, Reason: "This session may contain credentials. Push to unapproved remotes is blocked."}
		}
		return &Response{Decision: policy.VerdictAsk, Reason: "Git push to unapproved remote requires approval."}
	case policy.VerbPushOrigin:
		if req.Session.SecretSession {
			return &Response{Decision: policy.VerdictAsk, Reason: "This session may contain credentials. Push to approved remote requires approval."}
		}
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
	case policy.VerbNetAllowlisted:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		return &Response{
			Decision: policy.VerdictAsk,
			Reason:   fmt.Sprintf("Network request to %s. This host is in your security policy but still requires approval.", req.Intent.Target),
		}
	case policy.VerbDnsLookup:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		return &Response{
			Decision: policy.VerdictDeny,
			Reason:   fmt.Sprintf("DNS lookups can leak data. Blocked by default. (%s)", req.Intent.Target),
		}
	}
	return nil
}

func denyFlowResponse() *Response {
	return &Response{
		Decision: policy.VerdictDeny,
		Reason:   "Data labels on this action exceed the trust level of the destination.",
	}
}
