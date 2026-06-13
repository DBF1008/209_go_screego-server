package turn

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/randutil"
)

type RelayAddressGeneratorPortRange struct {
	MinPort uint16
	MaxPort uint16
	Rand    randutil.MathRandomGenerator
}

func (r *RelayAddressGeneratorPortRange) Validate() error {
	if r.Rand == nil {
		r.Rand = randutil.NewMathRandomGenerator()
	}

	return nil
}

func (r *RelayAddressGeneratorPortRange) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	if requestedPort != 0 {
		conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", requestedPort))
		if err != nil {
			return nil, nil, err
		}
		relayAddr := conn.LocalAddr().(*net.UDPAddr)
		return conn, relayAddr, nil
	}

	for try := 0; try < 10; try++ {
		port := r.MinPort + uint16(r.Rand.Intn(int((r.MaxPort+1)-r.MinPort)))
		conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue
		}

		relayAddr := conn.LocalAddr().(*net.UDPAddr)
		return conn, relayAddr, nil
	}

	return nil, nil, errors.New("could not find free port: max retries exceeded")
}

func (r *RelayAddressGeneratorPortRange) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	if requestedPort != 0 {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", requestedPort))
		if err != nil {
			return nil, nil, err
		}
		return &tcpRelayConn{listener: listener}, listener.Addr(), nil
	}

	for try := 0; try < 10; try++ {
		port := r.MinPort + uint16(r.Rand.Intn(int((r.MaxPort+1)-r.MinPort)))
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue
		}

		return &tcpRelayConn{listener: listener}, listener.Addr(), nil
	}

	return nil, nil, errors.New("could not find free port: max retries exceeded")
}

// tcpRelayConn adapts a net.Listener to the net.Conn that pion v4's
// RelayAddressGenerator.AllocateConn is required to return. A TURN TCP relay
// (RFC 6062) must listen for the peer's inbound connection, but the v4 interface
// hands back a single net.Conn (this was reworked to return a listener in v5).
// The reserved listener pins the relay port inside the configured range; the
// first read/write lazily accepts the single peer connection and all subsequent
// I/O is proxied to it.
type tcpRelayConn struct {
	listener net.Listener

	once    sync.Once
	conn    net.Conn
	dialErr error
}

// dial accepts the inbound peer connection exactly once and caches the result.
func (c *tcpRelayConn) dial() (net.Conn, error) {
	c.once.Do(func() {
		c.conn, c.dialErr = c.listener.Accept()
	})
	return c.conn, c.dialErr
}

func (c *tcpRelayConn) Read(b []byte) (int, error) {
	conn, err := c.dial()
	if err != nil {
		return 0, err
	}
	return conn.Read(b)
}

func (c *tcpRelayConn) Write(b []byte) (int, error) {
	conn, err := c.dial()
	if err != nil {
		return 0, err
	}
	return conn.Write(b)
}

func (c *tcpRelayConn) Close() error {
	// Disable (and unblock) any pending or future Accept, then tear down both
	// the reserved listener and the accepted peer connection, if any.
	c.once.Do(func() { c.dialErr = net.ErrClosed })
	err := c.listener.Close()
	if c.conn != nil {
		if cerr := c.conn.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// LocalAddr returns the relay address, i.e. the reserved listening socket.
func (c *tcpRelayConn) LocalAddr() net.Addr { return c.listener.Addr() }

func (c *tcpRelayConn) RemoteAddr() net.Addr {
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return nil
}

func (c *tcpRelayConn) SetDeadline(t time.Time) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	return conn.SetDeadline(t)
}

func (c *tcpRelayConn) SetReadDeadline(t time.Time) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	return conn.SetReadDeadline(t)
}

func (c *tcpRelayConn) SetWriteDeadline(t time.Time) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}
