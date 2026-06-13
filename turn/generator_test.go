package turn

import (
	"errors"
	"net"
	"testing"

	"github.com/screego/server/config/ipdns"
)

// errorProvider is an ipdns.Provider that always returns an error.
type errorProvider struct{ err error }

func (p *errorProvider) Get() (net.IP, net.IP, error) { return nil, nil, p.err }

// ---------------------------------------------------------------------------
// Generator.AllocateConn – external IP rewriting for TCP relay
// ---------------------------------------------------------------------------

func TestGenerator_AllocateConn_rewritesIPv4(t *testing.T) {
	externalIP := net.ParseIP("203.0.113.10")
	gen := &Generator{
		RelayAddressGenerator: &RelayAddressGeneratorNone{},
		IPProvider:            &ipdns.Static{V4: externalIP},
	}

	conn, addr, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer conn.Close()

	tcpAddr := addr.(*net.TCPAddr)
	if !tcpAddr.IP.Equal(externalIP) {
		t.Fatalf("expected relay IP %s, got %s", externalIP, tcpAddr.IP)
	}
	if tcpAddr.Port == 0 {
		t.Fatal("expected non-zero port")
	}
}

func TestGenerator_AllocateConn_rewritesIPv6(t *testing.T) {
	externalV6 := net.ParseIP("2001:db8::1")
	gen := &Generator{
		RelayAddressGenerator: &RelayAddressGeneratorNone{},
		// Only IPv6 available – no V4.
		IPProvider: &ipdns.Static{V4: nil, V6: externalV6},
	}

	conn, addr, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer conn.Close()

	tcpAddr := addr.(*net.TCPAddr)
	if !tcpAddr.IP.Equal(externalV6) {
		t.Fatalf("expected relay IP %s, got %s", externalV6, tcpAddr.IP)
	}
}

func TestGenerator_AllocateConn_prefersV4WhenLocalIsV4(t *testing.T) {
	// When both V4 and V6 are available and the local relay address is IPv4,
	// the Generator should prefer V4 (matching the AllocatePacketConn logic).
	externalV4 := net.ParseIP("198.51.100.5")
	externalV6 := net.ParseIP("2001:db8::5")
	gen := &Generator{
		RelayAddressGenerator: &RelayAddressGeneratorNone{},
		IPProvider:            &ipdns.Static{V4: externalV4, V6: externalV6},
	}

	conn, addr, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn failed: %v", err)
	}
	defer conn.Close()

	tcpAddr := addr.(*net.TCPAddr)
	// The local binding is 0.0.0.0 (IPv4), so V4 should be preferred.
	if !tcpAddr.IP.Equal(externalV4) {
		t.Fatalf("expected relay IP %s (V4 preferred), got %s", externalV4, tcpAddr.IP)
	}
}

func TestGenerator_AllocateConn_ipProviderError(t *testing.T) {
	providerErr := errors.New("dns lookup failed")
	gen := &Generator{
		RelayAddressGenerator: &RelayAddressGeneratorNone{},
		IPProvider:            &errorProvider{err: providerErr},
	}

	// Even though the underlying AllocateConn succeeds, the Generator should
	// propagate the IPProvider error.
	_, _, err := gen.AllocateConn("tcp", 0)
	if err == nil {
		t.Fatal("expected error from IPProvider")
	}
	if !errors.Is(err, providerErr) {
		t.Fatalf("expected %v, got %v", providerErr, err)
	}
}

func TestGenerator_AllocateConn_innerErrorPropagated(t *testing.T) {
	// Use a port that is already in use to force an inner AllocateConn error.
	blocker, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("could not get ephemeral port: %v", err)
	}
	defer blocker.Close()
	usedPort := blocker.Addr().(*net.TCPAddr).Port

	gen := &Generator{
		RelayAddressGenerator: &RelayAddressGeneratorNone{},
		IPProvider:            &ipdns.Static{V4: net.ParseIP("1.2.3.4")},
	}

	_, _, err = gen.AllocateConn("tcp", usedPort)
	if err == nil {
		t.Fatal("expected error when inner AllocateConn fails")
	}
}

// ---------------------------------------------------------------------------
// Generator.AllocatePacketConn – confirm existing UDP IP rewriting still works
// ---------------------------------------------------------------------------

func TestGenerator_AllocatePacketConn_rewritesIPv4(t *testing.T) {
	externalIP := net.ParseIP("203.0.113.20")
	gen := &Generator{
		RelayAddressGenerator: &RelayAddressGeneratorNone{},
		IPProvider:            &ipdns.Static{V4: externalIP},
	}

	conn, addr, err := gen.AllocatePacketConn("udp", 0)
	if err != nil {
		t.Fatalf("AllocatePacketConn failed: %v", err)
	}
	defer conn.Close()

	udpAddr := addr.(*net.UDPAddr)
	if !udpAddr.IP.Equal(externalIP) {
		t.Fatalf("expected relay IP %s, got %s", externalIP, udpAddr.IP)
	}
}

// ---------------------------------------------------------------------------
// Regression: AllocateConn no longer returns "todo"
// ---------------------------------------------------------------------------

func TestPortRange_AllocateConn_notTodo(t *testing.T) {
	gen := &RelayAddressGeneratorPortRange{
		MinPort: 49500,
		MaxPort: 49550,
	}
	if err := gen.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	conn, _, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn should not return an error, got: %v", err)
	}
	conn.Close()
}

func TestNone_AllocateConn_notTodo(t *testing.T) {
	gen := &RelayAddressGeneratorNone{}

	conn, _, err := gen.AllocateConn("tcp", 0)
	if err != nil {
		t.Fatalf("AllocateConn should not return an error, got: %v", err)
	}
	conn.Close()
}
