# Changelog

sir is experimental. Each release listed here is a snapshot of the "sandbox in reverse" model as it shipped, and entries are scoped to behavior users and contributors can actually observe.

This file tracks shipped releases only. Historical planning notes, launch copy, and exploratory findings live in git history rather than on the production repo surface.

## v0.1.2 — 2026-04-08

- Scoped hook-tamper detection and restore to real hook subtrees instead of whole settings files.
- Closed the Codex single-turn posture sweep gap by running a session-end sweep in the Stop path.
- Landed the first live MCP credential-leak catch against a real evil-MCP scenario.
- Tightened runtime posture messaging and support docs for Gemini and Codex.

## v0.1.1 — 2026-04-07

- Made corrupted or unreadable session and lease state fail closed instead of silently resetting.
- Locked Go fallback behavior to Rust policy parity for delegation and newly added verbs.
- Hardened the ledger hash chain with length-prefixed field encoding.
- Added the `sir version --check` path and tightened the supply-chain story around reproducible builds.

## v0.1.0 — 2026-04-06

- First public release with Claude reference support, Gemini near-parity support, and limited Codex support.
- Shipped hook-mediated IFC, shell classification, credential output scanning, MCP scanning, and the append-only ledger.
- Shipped `sir doctor`, `sir explain`, `sir audit`, `sir trace`, and the initial MCP proxy path.
- Released with signed artifacts, SBOM generation, reproducible-build checks, and zero external Rust dependencies.
