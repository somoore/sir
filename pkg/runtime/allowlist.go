package runtime

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

const wildcardPort = "*"

var defaultExternalDestinationPorts = []string{"22", "80", "443"}

type exactDestination struct {
	Host string
	Port string
}

func (d exactDestination) String() string {
	return d.Host + ":" + d.Port
}

type runtimeAllowlist struct {
	hosts        []string
	destinations []string
	portsByHost  map[string]map[string]struct{}
}

func buildRuntimeAllowlist(entries []string) runtimeAllowlist {
	hostSeen := map[string]struct{}{}
	destSeen := map[string]struct{}{}
	portsByHost := make(map[string]map[string]struct{})
	hosts := make([]string, 0, len(entries))
	destinations := make([]string, 0, len(entries)*2)

	for _, entry := range entries {
		for _, dest := range expandRuntimeDestinations(entry) {
			if _, ok := hostSeen[dest.Host]; !ok {
				hostSeen[dest.Host] = struct{}{}
				hosts = append(hosts, dest.Host)
			}
			if _, ok := portsByHost[dest.Host]; !ok {
				portsByHost[dest.Host] = make(map[string]struct{})
			}
			portsByHost[dest.Host][dest.Port] = struct{}{}
			key := dest.String()
			if _, ok := destSeen[key]; !ok {
				destSeen[key] = struct{}{}
				destinations = append(destinations, key)
			}
		}
	}

	sort.Strings(hosts)
	sort.Strings(destinations)
	return runtimeAllowlist{
		hosts:        hosts,
		destinations: destinations,
		portsByHost:  portsByHost,
	}
}

func (a runtimeAllowlist) Hosts() []string {
	return append([]string(nil), a.hosts...)
}

func (a runtimeAllowlist) Destinations() []string {
	return append([]string(nil), a.destinations...)
}

func (a runtimeAllowlist) Allows(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	ports := a.portsByHost[host]
	if len(ports) == 0 {
		return false
	}
	if _, ok := ports[wildcardPort]; ok {
		return true
	}
	_, ok := ports[port]
	return ok
}

func expandRuntimeDestinations(raw string) []exactDestination {
	host, port, explicitPort := parseRuntimeDestination(raw)
	if host == "" {
		return nil
	}
	if explicitPort {
		return []exactDestination{{Host: host, Port: port}}
	}
	if isLoopbackRuntimeHost(host) {
		return []exactDestination{{Host: host, Port: wildcardPort}}
	}
	dests := make([]exactDestination, 0, len(defaultExternalDestinationPorts))
	for _, candidate := range defaultExternalDestinationPorts {
		dests = append(dests, exactDestination{Host: host, Port: candidate})
	}
	return dests
}

func parseRuntimeDestination(raw string) (host, port string, explicitPort bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}

	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
			host = NormalizeProxyHost(parsed.Hostname())
			if parsed.Port() != "" {
				return host, normalizePort(parsed.Port()), true
			}
			if defaultPort := schemeDefaultPort(parsed.Scheme); defaultPort != "" {
				return host, defaultPort, true
			}
			return host, "", false
		}
	}

	if parsed, err := url.Parse("//" + raw); err == nil && parsed.Host != "" {
		host = NormalizeProxyHost(parsed.Hostname())
		if parsed.Port() != "" {
			return host, normalizePort(parsed.Port()), true
		}
	}
	return NormalizeProxyHost(raw), "", false
}

func schemeDefaultPort(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return "80"
	case "https":
		return "443"
	case "ssh":
		return "22"
	default:
		return ""
	}
}

func normalizePort(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return ""
	}
	return strings.TrimLeft(port, "+")
}

func isLoopbackRuntimeHost(host string) bool {
	host = NormalizeProxyHost(host)
	switch host {
	case "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
