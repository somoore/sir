package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func (p *LocalProxy) serveSOCKS() {
	for {
		conn, err := p.socksListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "sir: run proxy socks: %v\n", err)
			return
		}
		go p.serveSOCKSConn(conn)
	}
}

func (p *LocalProxy) serveSOCKSConn(conn net.Conn) {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		_ = conn.Close()
		return
	}
	if err := p.handshakeSOCKS(conn); err != nil {
		_ = conn.Close()
		return
	}
	host, port, err := readSOCKSConnectTarget(conn)
	if err != nil {
		writeSOCKSFailure(conn, 0x01)
		_ = conn.Close()
		return
	}
	host = NormalizeProxyHost(host)
	if !p.isAllowed(host, port) {
		p.recordBlockedEgress(net.JoinHostPort(host, port))
		writeSOCKSFailure(conn, 0x02)
		_ = conn.Close()
		return
	}
	p.recordAllowedEgress()

	upstream, err := p.dialAllowedTarget(context.Background(), "tcp", host, port)
	if err != nil {
		writeSOCKSFailure(conn, 0x05)
		_ = conn.Close()
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	go tunnelRunProxyConnections(upstream, conn)
	go tunnelRunProxyConnections(conn, upstream)
}

// HandshakeSOCKS performs the SOCKS5 greeting handshake. Exported for tests.
func (p *LocalProxy) HandshakeSOCKS(conn net.Conn) error {
	return p.handshakeSOCKS(conn)
}

func (p *LocalProxy) handshakeSOCKS(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unsupported socks version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == 0x00 {
			_, err := conn.Write([]byte{0x05, 0x00})
			return err
		}
	}
	_, err := conn.Write([]byte{0x05, 0xff})
	if err != nil {
		return err
	}
	return fmt.Errorf("no acceptable socks authentication method")
}

func readSOCKSConnectTarget(conn net.Conn) (string, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", err
	}
	if header[0] != 0x05 {
		return "", "", fmt.Errorf("unsupported socks version %d", header[0])
	}
	if header[1] != 0x01 {
		return "", "", fmt.Errorf("unsupported socks command %d", header[1])
	}
	var host string
	switch header[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", "", err
		}
		host = net.IP(addr).String()
	case 0x03:
		size := make([]byte, 1)
		if _, err := io.ReadFull(conn, size); err != nil {
			return "", "", err
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", "", err
		}
		host = string(name)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", "", err
		}
		host = net.IP(addr).String()
	default:
		return "", "", fmt.Errorf("unsupported socks address type %d", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", "", err
	}
	port := fmt.Sprintf("%d", int(portBytes[0])<<8|int(portBytes[1]))
	return host, port, nil
}

func writeSOCKSFailure(conn net.Conn, code byte) {
	_, _ = conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
