package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
)

func (p *LocalProxy) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.serveConnect(w, req)
		return
	}
	if req.URL == nil || req.URL.Host == "" {
		http.Error(w, "sir run proxy requires absolute request URLs", http.StatusBadRequest)
		return
	}

	host := NormalizeProxyHost(req.URL.Host)
	port := requestURLPort(req.URL)
	if !p.isAllowed(host, port) {
		http.Error(w, fmt.Sprintf("sir run proxy blocked destination %q", net.JoinHostPort(host, port)), http.StatusForbidden)
		return
	}

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	outReq.URL = cloneURL(req.URL)
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	outReq.Header = req.Header.Clone()
	outReq.Header.Del("Proxy-Connection")

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("sir run proxy upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *LocalProxy) serveConnect(w http.ResponseWriter, req *http.Request) {
	host := NormalizeProxyHost(req.Host)
	port := connectDialPort(req.Host)
	if !p.isAllowed(host, port) {
		http.Error(w, fmt.Sprintf("sir run proxy blocked destination %q", net.JoinHostPort(host, port)), http.StatusForbidden)
		return
	}

	upstream, err := p.dialAllowedTarget(req.Context(), "tcp", host, port)
	if err != nil {
		http.Error(w, fmt.Sprintf("sir run proxy upstream dial error: %v", err), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "sir run proxy cannot hijack CONNECT", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		http.Error(w, fmt.Sprintf("sir run proxy hijack failed: %v", err), http.StatusInternalServerError)
		return
	}

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		return
	}

	go tunnelRunProxyConnections(upstream, client)
	go tunnelRunProxyConnections(client, upstream)
}

func tunnelRunProxyConnections(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func (p *LocalProxy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host := NormalizeProxyHost(addr)
	if host == "" {
		return nil, fmt.Errorf("sir run proxy missing host for %q", addr)
	}
	port := "443"
	if _, parsedPort, err := net.SplitHostPort(addr); err == nil && parsedPort != "" {
		port = parsedPort
	}
	return p.dialAllowedTarget(ctx, network, host, port)
}
