module github.com/somoore/sir

// Minimum language version. sir uses only pre-1.21 stdlib (no slices,
// maps, iter, slog, cmp) so this floor is conservative, not driven by
// a specific feature requirement. Do NOT raise this to match a CI
// toolchain version — that's what the `toolchain` directive below is
// for. Raising the `go` directive only gates out users who could
// otherwise build fine.
go 1.22

// Build-time toolchain. CI, release.yml, and `go build` on a developer
// machine will auto-download and use Go 1.25.10 when this directive is
// present (GOTOOLCHAIN=auto is the default since Go 1.21). 1.25.10
// ships fixes for GO-2026-4971 (net Dial/LookupPort NUL byte panic on
// Windows) and GO-2026-4918 (HTTP/2 infinite loop on bad SETTINGS_MAX_FRAME_SIZE)
// on top of the crypto/x509 + crypto/tls CVEs (GO-2026-4947, GO-2026-4946,
// GO-2026-4870) carried since 1.25.9. Do not downgrade without replacing
// the pin with an equally-patched version.
toolchain go1.25.10
