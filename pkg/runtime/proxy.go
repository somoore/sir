package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// LocalProxy is the provider-aware local proxy used by the macOS runtime path.
type LocalProxy struct {
	server        *http.Server
	listener      net.Listener
	socksListener net.Listener
	transport     *http.Transport
	allowlist     runtimeAllowlist
	resolvedIPs   map[string]struct{}
	pinnedHosts   map[string][]string
	dial          func(context.Context, string, string) (net.Conn, error)
	statsMu       sync.Mutex
	stats         localProxyStats
}

type localProxyStats struct {
	allowedEgressCount int
	blockedEgressCount int
	lastBlockedDest    string
}

// StartLocalProxy starts the local HTTP CONNECT + SOCKS5 proxy used by
// `sir run` on macOS.
func StartLocalProxy(allowedHosts []string) (*LocalProxy, error) {
	return startLocalProxyWithAllowlist(buildRuntimeAllowlist(allowedHosts), net.DefaultResolver.LookupHost)
}

func startLocalProxyWithResolver(allowedHosts []string, resolver func(context.Context, string) ([]string, error)) (*LocalProxy, error) {
	return startLocalProxyWithAllowlist(buildRuntimeAllowlist(allowedHosts), resolver)
}

func startLocalProxyWithAllowlist(allowlist runtimeAllowlist, resolver func(context.Context, string) ([]string, error)) (*LocalProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		return nil, err
	}

	proxy := &LocalProxy{
		listener:      listener,
		socksListener: socksListener,
		allowlist:     allowlist,
		resolvedIPs:   make(map[string]struct{}),
		pinnedHosts:   make(map[string][]string),
		dial:          (&net.Dialer{}).DialContext,
	}
	if err := proxy.seedAllowlist(resolver); err != nil {
		listener.Close()
		socksListener.Close()
		return nil, err
	}
	proxy.transport = &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		DialContext:         proxy.dialContext,
	}

	proxy.server = &http.Server{
		Handler:           http.HandlerFunc(proxy.serveHTTP),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := proxy.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "sir: run proxy: %v\n", err)
		}
	}()
	go proxy.serveSOCKS()
	return proxy, nil
}

func (p *LocalProxy) URL() string {
	if p == nil || p.listener == nil {
		return ""
	}
	return "http://" + p.listener.Addr().String()
}

func (p *LocalProxy) SOCKSURL() string {
	if p == nil || p.socksListener == nil {
		return ""
	}
	return "socks5h://" + p.socksListener.Addr().String()
}

func (p *LocalProxy) Close() error {
	if p == nil || p.server == nil {
		return nil
	}
	var joined error
	if err := p.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		joined = errors.Join(joined, err)
	}
	if p.listener != nil {
		if err := p.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			joined = errors.Join(joined, err)
		}
	}
	if p.socksListener != nil {
		if err := p.socksListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func (p *LocalProxy) recordAllowedEgress() {
	if p == nil {
		return
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	p.stats.allowedEgressCount++
}

func (p *LocalProxy) recordBlockedEgress(dest string) {
	if p == nil {
		return
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	p.stats.blockedEgressCount++
	p.stats.lastBlockedDest = dest
}

func (p *LocalProxy) snapshotStats() localProxyStats {
	if p == nil {
		return localProxyStats{}
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	return p.stats
}
