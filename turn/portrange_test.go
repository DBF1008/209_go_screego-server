package turn

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rangeMin uint16 = 21000
	rangeMax uint16 = 21010
)

// newRange returns a validated port-range generator limited to [rangeMin, rangeMax].
func newRange(t *testing.T) *RelayAddressGeneratorPortRange {
	t.Helper()
	gen := &RelayAddressGeneratorPortRange{MinPort: rangeMin, MaxPort: rangeMax}
	require.NoError(t, gen.Validate())
	return gen
}

// freePort asks the OS for an unused port on the given network ("tcp"/"udp")
// and returns it after releasing the socket again.
func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp", ":0")
		require.NoError(t, err)
		port := conn.LocalAddr().(*net.UDPAddr).Port
		require.NoError(t, conn.Close())
		return port
	}
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func TestRelayAddressGeneratorPortRange_AllocatePacketConn_RandomPortInRange(t *testing.T) {
	conn, addr, err := newRange(t).AllocatePacketConn("udp", 0)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	udpAddr, ok := addr.(*net.UDPAddr)
	require.Truef(t, ok, "expected *net.UDPAddr, got %T", addr)
	assert.GreaterOrEqual(t, udpAddr.Port, int(rangeMin))
	assert.LessOrEqual(t, udpAddr.Port, int(rangeMax))
}

func TestRelayAddressGeneratorPortRange_AllocatePacketConn_RequestedPort(t *testing.T) {
	port := freePort(t, "udp")
	conn, addr, err := newRange(t).AllocatePacketConn("udp", port)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, port, addr.(*net.UDPAddr).Port)
}

func TestRelayAddressGeneratorPortRange_AllocateConn_RandomPortInRange(t *testing.T) {
	conn, addr, err := newRange(t).AllocateConn("tcp", 0)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	tcpAddr, ok := addr.(*net.TCPAddr)
	require.Truef(t, ok, "expected *net.TCPAddr, got %T", addr)
	assert.GreaterOrEqual(t, tcpAddr.Port, int(rangeMin))
	assert.LessOrEqual(t, tcpAddr.Port, int(rangeMax))

	// The returned conn must be backed by the reserved relay port.
	assert.Equal(t, tcpAddr.Port, conn.LocalAddr().(*net.TCPAddr).Port)
}

func TestRelayAddressGeneratorPortRange_AllocateConn_RequestedPort(t *testing.T) {
	port := freePort(t, "tcp")
	conn, addr, err := newRange(t).AllocateConn("tcp", port)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, port, addr.(*net.TCPAddr).Port)
}

func TestRelayAddressGeneratorPortRange_AllocateConn_NoFreePort(t *testing.T) {
	// Occupy the only port the generator is allowed to hand out so every
	// allocation attempt fails and the retry loop is exhausted.
	blocker, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer blocker.Close()
	port := uint16(blocker.Addr().(*net.TCPAddr).Port)

	gen := &RelayAddressGeneratorPortRange{MinPort: port, MaxPort: port}
	require.NoError(t, gen.Validate())

	conn, addr, err := gen.AllocateConn("tcp", 0)
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Nil(t, addr)
}

// staticProvider is a minimal ipdns.Provider returning fixed addresses.
type staticProvider struct {
	v4 net.IP
	v6 net.IP
}

func (s staticProvider) Get() (net.IP, net.IP, error) { return s.v4, s.v6, nil }

func TestGenerator_AllocateConn_RewritesRelayIP(t *testing.T) {
	gen := &Generator{
		RelayAddressGenerator: newRange(t),
		IPProvider:            staticProvider{v4: net.IPv4(203, 0, 113, 7)},
	}

	conn, addr, err := gen.AllocateConn("tcp", 0)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()

	tcpAddr, ok := addr.(*net.TCPAddr)
	require.Truef(t, ok, "expected *net.TCPAddr, got %T", addr)
	assert.Equal(t, "203.0.113.7", tcpAddr.IP.String())
	assert.GreaterOrEqual(t, tcpAddr.Port, int(rangeMin))
	assert.LessOrEqual(t, tcpAddr.Port, int(rangeMax))
}
