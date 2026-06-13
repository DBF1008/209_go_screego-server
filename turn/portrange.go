package turn

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/randutil"
)

// listenerConn adapts a net.Listener into a net.Conn suitable for TURN TCP
// relay allocation. The first Read (or Write) lazily accepts a single peer
// connection from the listener; subsequent I/O is proxied to that peer.
// Close tears down both the accepted peer connection and the listener.
type listenerConn struct {
	listener net.Listener

	mu      sync.Mutex
	peer    net.Conn
	initErr error
	done    bool
	closed  bool
}

func (c *listenerConn) init() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if c.done {
		err := c.initErr
		c.mu.Unlock()
		return err
	}
	c.done = true

	// Accept must run without holding the mutex so that Close (called from
	// another goroutine) can shut the listener down and unblock Accept.
	l := c.listener
	c.mu.Unlock()

	peer, err := l.Accept()

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.initErr = err
		return err
	}
	c.peer = peer
	return nil
}

func (c *listenerConn) Read(b []byte) (int, error) {
	if err := c.init(); err != nil {
		return 0, err
	}
	return c.peer.Read(b)
}

func (c *listenerConn) Write(b []byte) (int, error) {
	if err := c.init(); err != nil {
		return 0, err
	}
	return c.peer.Write(b)
}

func (c *listenerConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closed = true
	peer := c.peer
	c.mu.Unlock()

	var errs []error
	if peer != nil {
		if err := peer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.listener.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *listenerConn) LocalAddr() net.Addr {
	return c.listener.Addr()
}

func (c *listenerConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer != nil {
		return c.peer.RemoteAddr()
	}
	return c.listener.Addr()
}

func (c *listenerConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	peer := c.peer
	c.mu.Unlock()
	if peer != nil {
		return peer.SetDeadline(t)
	}
	return nil
}

func (c *listenerConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	peer := c.peer
	c.mu.Unlock()
	if peer != nil {
		return peer.SetReadDeadline(t)
	}
	return nil
}

func (c *listenerConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	peer := c.peer
	c.mu.Unlock()
	if peer != nil {
		return peer.SetWriteDeadline(t)
	}
	return nil
}

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
		relayAddr := listener.Addr().(*net.TCPAddr)
		lc := &listenerConn{listener: listener}
		return lc, relayAddr, nil
	}

	for try := 0; try < 10; try++ {
		port := r.MinPort + uint16(r.Rand.Intn(int((r.MaxPort+1)-r.MinPort)))
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue
		}
		relayAddr := listener.Addr().(*net.TCPAddr)
		lc := &listenerConn{listener: listener}
		return lc, relayAddr, nil
	}

	return nil, nil, errors.New("could not find free port: max retries exceeded")
}
