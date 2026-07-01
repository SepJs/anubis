// Package raw provides raw socket operations (CAP_NET_RAW) for crafting
// custom TCP packets, bypassing the OS TCP stack for stealth scanning.
package raw

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

type RawSocket struct {
	fd      int
	timeout time.Duration
}

func NewRawSocket(timeout time.Duration) *RawSocket {
	return &RawSocket{timeout: timeout}
}

func (rs *RawSocket) Open() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("raw socket requires CAP_NET_RAW: %w", err)
	}
	rs.fd = fd

	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &syscall.Timeval{
		Sec:  int64(rs.timeout / time.Second),
		Usec: int64(rs.timeout % time.Second / time.Microsecond),
	}); err != nil {
		syscall.Close(fd)
		return err
	}

	return nil
}

func (rs *RawSocket) Close() error {
	return syscall.Close(rs.fd)
}

func (rs *RawSocket) SendSYN(ip net.IP, port int) error {
	addr := syscall.SockaddrInet4{
		Port: port,
	}
	copy(addr.Addr[:], ip.To4())

	return syscall.Sendto(rs.fd, buildSYNPacket(), 0, &addr)
}

func (rs *RawSocket) SendCustomPacket(data []byte, ip net.IP, port int) error {
	addr := syscall.SockaddrInet4{
		Port: port,
	}
	copy(addr.Addr[:], ip.To4())

	return syscall.Sendto(rs.fd, data, 0, &addr)
}

func buildSYNPacket() []byte {
	packet := make([]byte, 40)

	packet[0] = 0x45
	packet[1] = 0x00
	packet[2] = 0x00
	packet[3] = 0x28
	packet[8] = 64
	packet[9] = 6

	packet[20] = 0x00
	packet[21] = 0x50
	packet[22] = 0x00
	packet[23] = 0x50

	packet[32] = 0x00
	packet[33] = 0x00
	packet[34] = 0x00
	packet[35] = 0x00
	packet[36] = 0x50
	packet[37] = 0x02
	packet[38] = 0x71
	packet[39] = 0x10

	return packet
}

func TCPConnect(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

func TCPConnectWithRaw(srcIP, dstIP net.IP, dstPort int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrInet4{
		Port: dstPort,
	}
	copy(addr.Addr[:], dstIP.To4())

	return syscall.Connect(fd, &addr)
}

func IsRawSocketAvailable() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}
