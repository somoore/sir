// Package posture owns posture-file hashing, managed-hook subtree drift
// detection, and hook tamper restore helpers.
//
// This package exists so contributors changing hook classification or
// tool-path policy do not need to load the posture/tamper implementation at
// the same time. pkg/hooks keeps thin compatibility shims for tests and for
// the remaining callers that still import hooks for these helpers.
package posture
