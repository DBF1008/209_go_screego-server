package turn

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/randutil"
)

// ---------------------------------------------------------------------------
// RelayAddressGeneratorPortRange – AllocateConn (TCP relay)
// ---------------------------------------------------------------------------

func TestPortRange_AllocateConn_withinRange(t *testing.T) {
	gen := &RelayAddressGeneratorPortRange{
		MinPort: 49152,
		MaxPort: 49200,
		Rand:    randutil.NewMathRandomGenerator(),
	}

	conn, addr, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer conn.Close()

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", addr)
	}
	if tcpAddr.Port < int(gen.MinPort) || tcpAddr.Port > int(gen.MaxPort) {
		t.Fatalf("port %d outside range [%d, %d]", tcpAddr.Port, gen.MinPort, gen.MaxPort)
	}
}

func TestPortRange_AllocateConn_requestedPort(t *testing.T) {
	// First, grab an OS-assigned port to use as the requested port.
	tmp, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("could not get ephemeral port: %v", err)
	}
	requestedPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	gen := &RelayAddressGeneratorPortRange{
		MinPort: 49152,
		MaxPort: 49200,
		Rand:    randutil.NewMathRandomGenerator(),
	}

	conn, addr, err := gen.AllocateConn("tcp", requestedPort)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer conn.Close()

	tcpAddr := addr.(*net.TCPAddr)
	if tcpAddr.Port != requestedPort {
		t.Fatalf("expected port %d, got %d", requestedPort, tcpAddr.Port)
	}
}

func TestPortRange_AllocateConn_multiplePortsUnique(t *testing.T) {
	gen := &RelayAddressGeneratorPortRange{
		MinPort: 49200,
		MaxPort: 49250,
		Rand:    randutil.NewMathRandomGenerator(),
	}

	const n = 10
	conns := make([]net.Conn, n)
	ports := map[int]bool{}

	for i := 0; i < n; i++ {
		conn, addr, err := gen.AllocateConn("tcp", 0)
		if err != nil {
			t.Fatalf("AllocateConn #%d failed: %v", i, err)
		}
		conns[i] = conn
		port := addr.(*net.TCPAddr).Port
		if ports[port] {
			t.Fatalf("duplicate port %d on allocation #%d", port, i)
		}
		ports[port] = true
	}
	for _, c := range conns {
		c.Close()
	}
}

func TestPortRange_AllocateConn_exhaustedRetries(t *testing.T) {
	// Use a 1-port range and occupy it.
	gen := &RelayAddressGeneratorPortRange{
		MinPort: 49300,
		MaxPort: 49300,
		Rand:    randutil.NewMathRandomGenerator(),
	}

	blocker, err := net.Listen("tcp", fmt.Sprintf(":%d", gen.MinPort))
	if err != nil {
		t.Skipf("could not bind port %d: %v", gen.MinPort, err)
	}
	defer blocker.Close()

	_, _, err = gen.AllocateConn("tcp", 0)
	if err == nil {
		t.Fatal("expected error when port range is exhausted")
	}
}

func TestPortRange_AllocateConn_requestedPortInUse(t *testing.T) {
	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("could not get ephemeral port: %v", err)
	}
	defer blocker.Close()
	usedPort := blocker.Addr().(*net.TCPAddr).Port

	gen := &RelayAddressGeneratorPortRange{
		MinPort: 49152,
		MaxPort: 49200,
		Rand:    randutil.NewMathRandomGenerator(),
	}

	_, _, err = gen.AllocateConn("tcp", usedPort)
	if err == nil {
		t.Fatal("expected error when requested port is already in use")
	}
}

// ---------------------------------------------------------------------------
// RelayAddressGeneratorPortRange – AllocatePacketConn (UDP, existing behavior)
// ---------------------------------------------------------------------------

func TestPortRange_AllocatePacketConn_withinRange(t *testing.T) {
	gen := &RelayAddressGeneratorPortRange{
		MinPort: 49350,
		MaxPort: 49400,
		Rand:    randutil.NewMathRandomGenerator(),
	}

	conn, addr, err := gen.AllocatePacketConn("udp", 0)
	if err != nil {
		t.Fatalf("AllocatePacketConn failed: %v", err)
	}
	defer conn.Close()

	udpAddr := addr.(*net.UDPAddr)
	if udpAddr.Port < int(gen.MinPort) || udpAddr.Port > int(gen.MaxPort) {
		t.Fatalf("port %d outside range [%d, %d]", udpAddr.Port, gen.MinPort, gen.MaxPort)
	}
}

// ---------------------------------------------------------------------------
// RelayAddressGeneratorNone – AllocateConn (TCP relay)
// ---------------------------------------------------------------------------

func TestNone_AllocateConn_success(t *testing.T) {
	gen := &RelayAddressGeneratorNone{}

	conn, addr, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer conn.Close()

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", addr)
	}
	if tcpAddr.Port == 0 {
		t.Fatal("expected non-zero port from OS-assigned allocation")
	}
}

func TestNone_AllocateConn_requestedPort(t *testing.T) {
	tmp, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("could not get ephemeral port: %v", err)
	}
	requestedPort := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	gen := &RelayAddressGeneratorNone{}
	conn, addr, err := gen.AllocateConn("tcp", requestedPort)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer conn.Close()

	tcpAddr := addr.(*net.TCPAddr)
	if tcpAddr.Port != requestedPort {
		t.Fatalf("expected port %d, got %d", requestedPort, tcpAddr.Port)
	}
}

func TestNone_AllocateConn_portInUse(t *testing.T) {
	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("could not get ephemeral port: %v", err)
	}
	defer blocker.Close()
	usedPort := blocker.Addr().(*net.TCPAddr).Port

	gen := &RelayAddressGeneratorNone{}
	_, _, err = gen.AllocateConn("tcp", usedPort)
	if err == nil {
		t.Fatal("expected error when requested port is already in use")
	}
}

// ---------------------------------------------------------------------------
// listenerConn – proxy behavior
// ---------------------------------------------------------------------------

func TestListenerConn_acceptAndRelay(t *testing.T) {
	// Create a TCP listener via AllocateConn.
	gen := &RelayAddressGeneratorNone{}
	relayConn, addr, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer relayConn.Close()

	// Dial into the relay listener (simulates the peer).
	peerData := []byte("hello from peer")
	relayData := []byte("hello from relay")

	done := make(chan struct{})
	go func() {
		defer close(done)
		peer, err := net.DialTCP("tcp", nil, addr.(*net.TCPAddr))
		if err != nil {
			t.Errorf("peer dial failed: %v", err)
			return
		}
		defer peer.Close()

		// Send data to relay.
		if _, err := peer.Write(peerData); err != nil {
			t.Errorf("peer write failed: %v", err)
			return
		}

		// Read data from relay.
		buf := make([]byte, len(relayData))
		if _, err := peer.Read(buf); err != nil {
			t.Errorf("peer read failed: %v", err)
			return
		}
		if string(buf) != string(relayData) {
			t.Errorf("peer got %q, want %q", buf, relayData)
		}
	}()

	// Read from relayConn (triggers Accept).
	buf := make([]byte, len(peerData))
	relayConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := relayConn.Read(buf)
	if err != nil {
		t.Fatalf("relay read failed: %v", err)
	}
	if string(buf[:n]) != string(peerData) {
		t.Fatalf("relay got %q, want %q", buf[:n], peerData)
	}

	// Write back through relayConn.
	if _, err := relayConn.Write(relayData); err != nil {
		t.Fatalf("relay write failed: %v", err)
	}

	// Wait for the peer goroutine to finish.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("peer goroutine timed out")
	}
}

func TestListenerConn_closeUnblocksAccept(t *testing.T) {
	gen := &RelayAddressGeneratorNone{}
	relayConn, _, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}

	// Start a goroutine that triggers Accept via Read.
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := relayConn.Read(buf)
		readDone <- err
	}()

	// Give the Read goroutine a moment to enter Accept.
	time.Sleep(50 * time.Millisecond)

	// Close should unblock Accept.
	if err := relayConn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected error from Read after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

func TestListenerConn_doubleClose(t *testing.T) {
	gen := &RelayAddressGeneratorNone{}
	relayConn, _, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}

	if err := relayConn.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	err = relayConn.Close()
	if err != net.ErrClosed {
		t.Fatalf("expected net.ErrClosed on double close, got %v", err)
	}
}

func TestListenerConn_localAddr(t *testing.T) {
	gen := &RelayAddressGeneratorNone{}
	relayConn, addr, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer relayConn.Close()

	localAddr := relayConn.LocalAddr().(*net.TCPAddr)
	expectedAddr := addr.(*net.TCPAddr)
	if localAddr.Port != expectedAddr.Port {
		t.Fatalf("LocalAddr port %d != expected %d", localAddr.Port, expectedAddr.Port)
	}
}
