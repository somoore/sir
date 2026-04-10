package core

import "github.com/somoore/sir/pkg/policy"

// localEvaluate provides a fallback when mister-core is not available.
func localEvaluate(req *Request) (*Response, error) {
	if resp := localEvaluatePreflight(req); resp != nil {
		return resp, nil
	}

	effectiveLabels := append([]Label{}, req.Intent.Labels...)
	effectiveLabels = append(effectiveLabels, req.Intent.DerivedLabels...)

	if resp := localEvaluateNetwork(req, effectiveLabels); resp != nil {
		return resp, nil
	}
	if resp := localEvaluateDelegation(req); resp != nil {
		return resp, nil
	}
	if resp := localEvaluateCommandRisk(req); resp != nil {
		return resp, nil
	}
	if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
		return denyFlowResponse(), nil
	}

	return &Response{
		Decision: policy.VerdictAllow,
		Reason:   "Allowed by your security policy.",
	}, nil
}
