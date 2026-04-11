package ledger

import "fmt"

// GetLastEntry returns the most recent ledger entry, or nil if the ledger is empty.
func GetLastEntry(projectRoot string) (*Entry, error) {
	entries, err := ReadAll(projectRoot)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	e := entries[len(entries)-1]
	return &e, nil
}

// GetEntryByIndex returns a specific ledger entry by index.
// Returns nil if the index is out of range.
func GetEntryByIndex(projectRoot string, index int) (*Entry, []Entry, error) {
	entries, err := ReadAll(projectRoot)
	if err != nil {
		return nil, nil, err
	}
	if index < 0 || index >= len(entries) {
		return nil, entries, fmt.Errorf("index %d out of range (ledger has %d entries)", index, len(entries))
	}
	e := entries[index]
	return &e, entries, nil
}

// FindCausalSecretRead scans backwards from the given index to find the ledger
// entry that first set the session's secret flag. This is typically a read_ref
// with sensitivity=secret and decision=ask (approved by the developer), or an
// env_read that triggered session secret marking.
// Returns nil if no causal secret read is found.
func FindCausalSecretRead(entries []Entry, beforeIndex int) *Entry {
	for i := beforeIndex - 1; i >= 0; i-- {
		e := entries[i]
		if e.Sensitivity == "secret" && (e.Decision == "ask" || e.Decision == "allow") {
			return &e
		}
		if e.Verb == "env_read" && (e.Decision == "ask" || e.Decision == "allow") {
			return &e
		}
	}
	return nil
}

// FindRelatedEntries finds entries related to a given entry for causal chain construction.
// It returns entries that share the same session context (same target, same verb category,
// or entries that contributed to the current security state).
func FindRelatedEntries(entries []Entry, targetIndex int) []Entry {
	if targetIndex < 0 || targetIndex >= len(entries) {
		return nil
	}
	target := entries[targetIndex]
	var related []Entry

	if target.Decision == "deny" {
		causal := FindCausalSecretRead(entries, targetIndex)
		if causal != nil {
			related = append(related, *causal)
		}
	}

	for i := 0; i < targetIndex; i++ {
		e := entries[i]
		if e.Sensitivity == "secret" && (e.Decision == "ask" || e.Decision == "allow") && !entryIncluded(related, e.Index) {
			related = append(related, e)
		}
	}

	return related
}

func entryIncluded(entries []Entry, index int) bool {
	for _, entry := range entries {
		if entry.Index == index {
			return true
		}
	}
	return false
}
