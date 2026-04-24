package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

const (
	ContainmentModeDarwinProxy    = "darwin_local_proxy"
	ContainmentModeLinuxNamespace = "linux_network_namespace_offline"
	ContainmentModeLinuxAllowlist = "linux_network_namespace_allowlist"
	proxyResolverTimeout          = 2 * time.Second
	proxyDialAttemptTimeout       = 2 * time.Second
)

func (p *LocalProxy) seedAllowlist(resolver func(context.Context, string) ([]string, error)) error {
	for _, host := range p.allowlist.Hosts() {
		normalized := NormalizeProxyHost(host)
		if normalized == "" {
			continue
		}
		if ip := net.ParseIP(normalized); ip != nil {
			p.resolvedIPs[ip.String()] = struct{}{}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), proxyResolverTimeout)
		addrs, err := resolver(ctx, normalized)
		cancel()
		if err != nil {
			return fmt.Errorf("resolve allowed host %q: %w", normalized, err)
		}
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil {
				clean := ip.String()
				p.resolvedIPs[clean] = struct{}{}
				p.pinnedHosts[normalized] = appendUniquePinnedIP(p.pinnedHosts[normalized], clean)
			}
		}
	}
	return nil
}

func appendUniquePinnedIP(existing []string, ip string) []string {
	for _, cur := range existing {
		if cur == ip {
			return existing
		}
	}
	return append(existing, ip)
}

func (p *LocalProxy) allowedDialTargets(host, port string) []string {
	if p == nil {
		return nil
	}
	host = NormalizeProxyHost(host)
	port = normalizePort(port)
	if host == "" || port == "" || !p.isAllowed(host, port) {
		return nil
	}
	if pinned := p.pinnedHosts[host]; len(pinned) > 0 {
		targets := make([]string, 0, len(pinned))
		for _, ip := range pinned {
			targets = append(targets, net.JoinHostPort(ip, port))
		}
		return targets
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{net.JoinHostPort(ip.String(), port)}
	}
	return []string{net.JoinHostPort(host, port)}
}

func (p *LocalProxy) dialAllowedTarget(ctx context.Context, network, host, port string) (net.Conn, error) {
	if p == nil {
		return nil, fmt.Errorf("sir run proxy unavailable")
	}
	host = NormalizeProxyHost(host)
	if host == "" {
		return nil, fmt.Errorf("sir run proxy missing host")
	}
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var lastErr error
	for _, target := range p.allowedDialTargets(host, port) {
		attemptCtx, cancel := context.WithTimeout(ctx, boundedDialTimeout(ctx, proxyDialAttemptTimeout))
		conn, err := dial(attemptCtx, network, target)
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no dial targets for %q", host)
	}
	return nil, fmt.Errorf("sir run proxy upstream dial error for host %q: %w", host, lastErr)
}

func boundedDialTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		return 0
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Millisecond
		}
		if remaining < fallback {
			return remaining
		}
	}
	return fallback
}

func cloneURL(in *url.URL) *url.URL {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func copyHeaders(dst, src http.Header) {
	for k, values := range src {
		for _, value := range values {
			dst.Add(k, value)
		}
	}
}

func (p *LocalProxy) isAllowed(host, port string) bool {
	return p.allowlist.Allows(host, port)
}

// RunProxyAllowedHosts computes the effective provider/runtime allowlist for
// the macOS proxy path.
func RunProxyAllowedHosts(projectRoot string, opts Options) ([]string, error) {
	allowlist, err := buildRuntimeAllowlistForProject(projectRoot, opts)
	if err != nil {
		return nil, err
	}
	return allowlist.Hosts(), nil
}

// RunProxyAllowedDestinations computes the exact destination policy for the
// macOS proxy path.
func RunProxyAllowedDestinations(projectRoot string, opts Options) ([]string, error) {
	allowlist, err := buildRuntimeAllowlistForProject(projectRoot, opts)
	if err != nil {
		return nil, err
	}
	return allowlist.Destinations(), nil
}

func buildRuntimeAllowlistForProject(projectRoot string, opts Options) (runtimeAllowlist, error) {
	l, err := loadRuntimeLease(projectRoot)
	if err != nil {
		return runtimeAllowlist{}, err
	}
	activeHosts := l.ActiveApprovedHosts()
	merged := make([]string, 0, len(activeHosts)+len(opts.AllowedHosts))
	merged = append(merged, activeHosts...)
	if spec := opts.Agent.GetSpec(); spec != nil {
		merged = append(merged, spec.RuntimeProxyHosts...)
	}
	merged = append(merged, opts.AllowedHosts...)
	return buildRuntimeAllowlist(merged), nil
}

func loadRuntimeLease(projectRoot string) (*lease.Lease, error) {
	path := filepath.Join(session.DurableStateDir(projectRoot), "lease.json")
	l, err := lease.Load(path)
	if os.IsNotExist(err) {
		return lease.DefaultLease(), nil
	}
	return l, err
}

// NormalizeProxyHost canonicalizes host strings for runtime allowlist checks.
func NormalizeProxyHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
			raw = parsed.Host
		}
	}
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	raw = strings.TrimSuffix(raw, ".")
	return strings.ToLower(raw)
}

func connectDialPort(rawHostport string) string {
	if _, parsedPort, err := net.SplitHostPort(rawHostport); err == nil && parsedPort != "" {
		return parsedPort
	}
	return "443"
}

func requestURLPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if port := u.Port(); port != "" {
		return normalizePort(port)
	}
	return schemeDefaultPort(u.Scheme)
}
