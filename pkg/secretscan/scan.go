package secretscan

import "regexp"

// CredentialMatch describes a detected credential pattern.
// Never stores the actual matched value.
type CredentialMatch struct {
	PatternName string
	Confidence  string // "high" or "medium"
}

type Pattern struct {
	Name           string
	RedactionLabel string
	RE             *regexp.Regexp
	Confidence     string
	Validator      func(match string) bool
}
