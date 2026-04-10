package runtime

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
)

type linuxResolvedDestination struct {
	Host string
	IP   string
	Port string
}

func resolveRuntimeDestinations(allowlist runtimeAllowlist, resolver func(context.Context, string) ([]string, error)) ([]linuxResolvedDestination, error) {
	out := make([]linuxResolvedDestination, 0, len(allowlist.Destinations()))
	seen := map[string]struct{}{}
	for _, host := range allowlist.Hosts() {
		ports := allowlist.portsByHost[host]
		if len(ports) == 0 {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			for port := range ports {
				if port == wildcardPort {
					continue
				}
				key := host + "|" + ip.String() + "|" + port
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, linuxResolvedDestination{Host: host, IP: ip.String(), Port: port})
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), proxyResolverTimeout)
		addrs, err := resolver(ctx, host)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("resolve allowed host %q: %w", host, err)
		}
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip == nil {
				continue
			}
			for port := range ports {
				if port == wildcardPort {
					continue
				}
				key := host + "|" + ip.String() + "|" + port
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, linuxResolvedDestination{Host: host, IP: ip.String(), Port: port})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		leftPort, leftErr := strconv.Atoi(out[i].Port)
		rightPort, rightErr := strconv.Atoi(out[j].Port)
		if leftErr == nil && rightErr == nil && leftPort != rightPort {
			return leftPort < rightPort
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

func linuxHostsLines(resolved []linuxResolvedDestination) []string {
	lines := make([]string, 0, len(resolved))
	seen := map[string]struct{}{}
	for _, dest := range resolved {
		if net.ParseIP(dest.Host) != nil || isLoopbackRuntimeHost(dest.Host) {
			continue
		}
		line := dest.IP + "\t" + dest.Host
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

func splitLinuxResolvedDestinations(resolved []linuxResolvedDestination) (ipv4 []linuxResolvedDestination, ipv6 []linuxResolvedDestination) {
	ipv4 = make([]linuxResolvedDestination, 0, len(resolved))
	ipv6 = make([]linuxResolvedDestination, 0, len(resolved))
	for _, dest := range resolved {
		ip := net.ParseIP(dest.IP)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, dest)
			continue
		}
		ipv6 = append(ipv6, dest)
	}
	return ipv4, ipv6
}
