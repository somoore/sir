package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func TestRunProxyAllowedHostsMergesLeaseAgentAndFlags(t *testing.T) {
	env := newTestEnv(t)
	l := lease.DefaultLease()
	l.ApprovedHosts = append(l.ApprovedHosts, "docs.internal.example")
	if err := l.Save(filepath.Join(session.DurableStateDir(env.projectRoot), "lease.json")); err != nil {
		t.Fatal(err)
	}

	hosts, err := runProxyAllowedHosts(env.projectRoot, runOptions{
		agent:        agent.NewClaudeAgent(),
		allowedHosts: []string{"API.Anthropic.com", "preview.example.com"},
	})
	if err != nil {
		t.Fatalf("runProxyAllowedHosts: %v", err)
	}

	for _, want := range []string{
		"api.anthropic.com",
		"docs.internal.example",
		"preview.example.com",
		"localhost",
	} {
		if !containsString(hosts, want) {
			t.Fatalf("effective runtime host policy missing %q: %v", want, hosts)
		}
	}
}

func TestRunProxyAllowedDestinationsExpandToExactDestinations(t *testing.T) {
	env := newTestEnv(t)
	l := lease.DefaultLease()
	l.ApprovedHosts = append(l.ApprovedHosts, "docs.internal.example:8443")
	if err := l.Save(filepath.Join(session.DurableStateDir(env.projectRoot), "lease.json")); err != nil {
		t.Fatal(err)
	}

	destinations, err := runProxyAllowedDestinations(env.projectRoot, runOptions{
		agent:        agent.NewClaudeAgent(),
		allowedHosts: []string{"preview.example.com"},
	})
	if err != nil {
		t.Fatalf("runProxyAllowedDestinations: %v", err)
	}

	for _, want := range []string{
		"api.anthropic.com:443",
		"docs.internal.example:8443",
		"preview.example.com:443",
		"localhost:*",
	} {
		if !containsString(destinations, want) {
			t.Fatalf("effective runtime destination policy missing %q: %v", want, destinations)
		}
	}
	if containsString(destinations, "preview.example.com:8443") {
		t.Fatalf("unexpected non-default destination expansion: %v", destinations)
	}
}

func TestSeedRunShadowStateCopiesLease(t *testing.T) {
	env := newTestEnv(t)
	l := lease.DefaultLease()
	l.ApprovedHosts = append(l.ApprovedHosts, "runtime.example.com")
	durableLeasePath := filepath.Join(session.DurableStateDir(env.projectRoot), "lease.json")
	if err := l.Save(durableLeasePath); err != nil {
		t.Fatal(err)
	}

	stateHome := t.TempDir()
	if err := seedRunShadowState(env.projectRoot, stateHome); err != nil {
		t.Fatalf("seedRunShadowState: %v", err)
	}

	shadowLease, err := lease.Load(filepath.Join(session.StateDirUnder(stateHome, env.projectRoot), "lease.json"))
	if err != nil {
		t.Fatalf("load shadow lease: %v", err)
	}
	if !containsString(shadowLease.ApprovedHosts, "runtime.example.com") {
		t.Fatalf("shadow lease missing copied approved host: %+v", shadowLease.ApprovedHosts)
	}
}

func TestSeedRunShadowStateCopiesExistingSession(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	durableState := session.NewState(env.projectRoot)
	durableState.MarkSecretSession()
	env.writeSession(durableState)

	stateHome := t.TempDir()
	if err := seedRunShadowState(env.projectRoot, stateHome); err != nil {
		t.Fatalf("seedRunShadowState: %v", err)
	}

	shadowState, err := session.LoadFromHome(stateHome, env.projectRoot)
	if err != nil {
		t.Fatalf("load shadow session: %v", err)
	}
	if !shadowState.SecretSession {
		t.Fatalf("expected shadow session to preserve secret flag: %+v", shadowState)
	}
}

func TestRunLocalProxyAllowsHTTPToApprovedHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxy, err := startRunLocalProxy([]string{normalizeRunProxyHost(upstream.URL)})
	if err != nil {
		t.Fatalf("startRunLocalProxy: %v", err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unexpected proxy response: %d %q", resp.StatusCode, string(body))
	}
}

func TestRunLocalProxyBlocksHTTPToUnapprovedHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxy, err := startRunLocalProxy([]string{"127.0.0.2"})
	if err != nil {
		t.Fatalf("startRunLocalProxy: %v", err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked host, got %d", resp.StatusCode)
	}
}

func TestRunLocalProxyAllowsHTTPSConnectToApprovedHosts(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))
	defer upstream.Close()

	proxy, err := startRunLocalProxy([]string{normalizeRunProxyHost(upstream.URL)})
	if err != nil {
		t.Fatalf("startRunLocalProxy: %v", err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test server only
		},
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("HTTPS GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secure" {
		t.Fatalf("unexpected HTTPS proxy response: %d %q", resp.StatusCode, string(body))
	}
}

func TestRunLocalProxyAllowsSOCKS5ToApprovedHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("socks-ok"))
	}))
	defer upstream.Close()

	proxy, err := startRunLocalProxy([]string{normalizeRunProxyHost(upstream.URL)})
	if err != nil {
		t.Fatalf("startRunLocalProxy: %v", err)
	}
	defer proxy.Close()

	socksURL, _ := url.Parse(proxy.SOCKSURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(socksURL)},
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET via socks5 proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "socks-ok" {
		t.Fatalf("unexpected socks5 proxy response: %d %q", resp.StatusCode, string(body))
	}
}

func TestRunLocalProxyBlocksSOCKS5ToUnapprovedHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("socks-ok"))
	}))
	defer upstream.Close()

	proxy, err := startRunLocalProxy([]string{"127.0.0.2"})
	if err != nil {
		t.Fatalf("startRunLocalProxy: %v", err)
	}
	defer proxy.Close()

	socksURL, _ := url.Parse(proxy.SOCKSURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(socksURL)},
	}

	if _, err := client.Get(upstream.URL); err == nil {
		t.Fatal("expected socks5 proxy request to fail for blocked host")
	}
}

func TestHandshakeSOCKSRejectsUnsupportedAuthMethods(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	proxy := &runLocalProxy{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.HandshakeSOCKS(server)
	}()

	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write socks greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read socks rejection: %v", err)
	}
	if got := string(reply); got != string([]byte{0x05, 0xff}) {
		t.Fatalf("unexpected socks rejection reply: %v", reply)
	}
	if err := <-errCh; err == nil {
		t.Fatal("expected handshakeSOCKS to fail when no acceptable auth method is offered")
	}
}

func TestNormalizeRunProxyHost(t *testing.T) {
	tests := map[string]string{
		"API.OpenAI.com":                        "api.openai.com",
		"https://api.anthropic.com/v1/messages": "api.anthropic.com",
		"generativelanguage.googleapis.com:443": "generativelanguage.googleapis.com",
		"[::1]:8080":                            "::1",
	}
	for input, want := range tests {
		if got := normalizeRunProxyHost(input); got != want {
			t.Fatalf("normalizeRunProxyHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCmdStatusReportsActiveRuntimeContainment(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
						},
					},
				},
			},
		},
	}
	env.writeSettingsJSON(settings)

	shadowHome := t.TempDir()
	shadowState := session.NewState(env.projectRoot)
	shadowState.MarkSecretSession()
	if err := seedRunShadowState(env.projectRoot, shadowHome); err != nil {
		t.Fatal(err)
	}
	t.Setenv(session.StateHomeEnvVar, shadowHome)
	if err := shadowState.Save(); err != nil {
		t.Fatalf("save shadow session: %v", err)
	}
	t.Setenv(session.StateHomeEnvVar, "")

	if err := session.SaveRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:             string(agent.Claude),
		Mode:                runContainmentModeDarwinProxy,
		ProxyURL:            "http://127.0.0.1:39999",
		SOCKSProxyURL:       "socks5://127.0.0.1:40000",
		ProxyProtocols:      []string{"http-connect", "socks5"},
		AllowedHosts:        []string{"api.anthropic.com", "localhost"},
		AllowedDestinations: []string{"api.anthropic.com:443", "localhost:*"},
		MaskedHostSockets:   []string{"/tmp/ssh-agent.sock"},
		ShadowStateHome:     shadowHome,
		HeartbeatAt:         time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.RemoveRuntimeContainment(env.projectRoot) })

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})
	for _, want := range []string{
		"runtime   degraded (claude via darwin_local_proxy)",
		"Proxy surface: http-connect, socks5",
		"Egress allowlist: api.anthropic.com, localhost",
		"Exact destinations: api.anthropic.com:443, localhost:*",
		"Masked host sockets: /tmp/ssh-agent.sock",
		"secrets   ACTIVE",
		"shadow",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdStatusReportsStaleRuntimeContainment(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
						},
					},
				},
			},
		},
	}
	env.writeSettingsJSON(settings)
	if err := session.SaveRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:         string(agent.Claude),
		Mode:            runContainmentModeDarwinProxy,
		ShadowStateHome: filepath.Join(t.TempDir(), "sir-run-state-missing"),
		StartedAt:       time.Now().Add(-time.Minute),
		HeartbeatAt:     time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.RemoveRuntimeContainment(env.projectRoot) })

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})
	for _, want := range []string{
		"runtime   stale (claude via darwin_local_proxy)",
		"Reason: shadow state directory missing",
		"Fix: rerun `sir run claude` to rebuild the host boundary",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdStatusReportsDegradedRuntimeContainment(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSettingsJSON(map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
						},
					},
				},
			},
		},
	})
	shadowHome := t.TempDir()
	shadowState := session.NewState(env.projectRoot)
	env.writeSession(shadowState)
	if err := os.MkdirAll(session.StateDirUnder(shadowHome, env.projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(session.StatePathUnder(shadowHome, env.projectRoot), mustJSON(t, shadowState), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := session.SaveRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:           string(agent.Claude),
		Mode:              runContainmentModeDarwinProxy,
		ProxyURL:          "http://127.0.0.1:7777",
		ShadowStateHome:   shadowHome,
		StartedAt:         time.Now().Add(-time.Minute),
		HeartbeatAt:       time.Now(),
		MaskedHostSockets: []string{"/tmp/ssh-agent.sock"},
		ScrubbedEnvVars:   []string{"SSH_AUTH_SOCK"},
		DegradedReasons: []string{
			"proxy-shaped enforcement: direct non-proxy sockets remain outside the exact-destination boundary on macOS",
		},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.RemoveRuntimeContainment(env.projectRoot) })

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})
	for _, want := range []string{
		"runtime   degraded (claude via darwin_local_proxy)",
		"Reason: proxy-shaped enforcement: direct non-proxy sockets remain outside the exact-destination boundary on macOS",
		"Impact: direct non-proxy sockets remain outside the exact-destination boundary on this platform",
		"Scrubbed host-control env: SSH_AUTH_SOCK",
		"Fix: prefer Linux exact-destination containment for the strongest below-hook boundary",
		"Fix: relaunch from a minimal env, for example: env -u SSH_AUTH_SOCK sir run claude",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdStatusReportsLastRuntimeReceipt(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSettingsJSON(map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
						},
					},
				},
			},
		},
	})
	env.writeSession(session.NewState(env.projectRoot))

	if err := session.SaveLastRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:                 string(agent.Claude),
		Mode:                    runContainmentModeDarwinProxy,
		ProxyProtocols:          []string{"http-connect", "socks5"},
		AllowedHosts:            []string{"api.anthropic.com", "localhost"},
		AllowedHostCount:        2,
		AllowedDestinations:     []string{"api.anthropic.com:443", "localhost:*"},
		AllowedDestinationCount: 2,
		DegradedReasons: []string{
			"proxy-shaped enforcement: direct non-proxy sockets remain outside the exact-destination boundary on macOS",
		},
		AllowedEgressCount:     3,
		BlockedEgressCount:     1,
		LastBlockedDestination: "api.anthropic.com:8443",
		EndedAt:                time.Date(2026, time.April, 10, 20, 0, 0, 0, time.UTC),
		ExitCode:               0,
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})
	for _, want := range []string{
		"runtime   last (claude via darwin_local_proxy)",
		"Policy size: 2 host(s), 2 destination(s)",
		"Egress events: 3 allowed, 1 blocked",
		"Last blocked destination: api.anthropic.com:8443",
		"Last exit: 0 at 2026-04-10T20:00:00Z",
		"Last launch degraded: proxy-shaped enforcement: direct non-proxy sockets remain outside the exact-destination boundary on macOS",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
