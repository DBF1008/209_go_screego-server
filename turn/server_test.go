package turn

import (
	"net"
	"sync"
	"testing"

	"github.com/pion/turn/v4"
)

// --- test helpers ---

func newTestServer() *InternalServer {
	return &InternalServer{lookup: map[string]Entry{}}
}

func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

func tcpAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// customAddr is an unknown net.Addr implementation used to verify that
// extractIP returns nil (and auth fails) for unrecognized address types.
type customAddr struct{}

func (customAddr) Network() string { return "custom" }
func (customAddr) String() string  { return "custom" }

// --- extractIP tests ---

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     net.Addr
		expected string
	}{
		{"UDP IPv4", udpAddr("1.2.3.4", 100), "1.2.3.4"},
		{"TCP IPv4", tcpAddr("5.6.7.8", 200), "5.6.7.8"},
		{"UDP IPv6", udpAddr("::1", 300), "::1"},
		{"TCP IPv6", tcpAddr("2001:db8::1", 400), "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := extractIP(tt.addr)
			if ip == nil {
				t.Fatal("extractIP returned nil")
			}
			if ip.String() != tt.expected {
				t.Fatalf("extractIP: got %s, want %s", ip, tt.expected)
			}
		})
	}
}

func TestExtractIP_UnknownType(t *testing.T) {
	ip := extractIP(customAddr{})
	if ip != nil {
		t.Fatalf("expected nil for unknown addr type, got %v", ip)
	}
}

// --- authenticate: matching IP succeeds ---

func TestAuthenticate_SameIP_UDP(t *testing.T) {
	svr := newTestServer()
	password := "testpassword"
	clientIP := net.ParseIP("192.168.1.100")
	svr.allow("user1", password, clientIP)

	key, ok := svr.authenticate("user1", Realm, udpAddr("192.168.1.100", 12345))
	if !ok {
		t.Fatal("expected authentication to succeed for matching IP over UDP")
	}
	expected := turn.GenerateAuthKey("user1", Realm, password)
	if string(key) != string(expected) {
		t.Fatalf("returned key mismatch: got %v, want %v", key, expected)
	}
}

func TestAuthenticate_SameIP_TCP(t *testing.T) {
	svr := newTestServer()
	password := "testpassword"
	clientIP := net.ParseIP("10.0.0.5")
	svr.allow("user2", password, clientIP)

	key, ok := svr.authenticate("user2", Realm, tcpAddr("10.0.0.5", 54321))
	if !ok {
		t.Fatal("expected authentication to succeed for matching IP over TCP")
	}
	expected := turn.GenerateAuthKey("user2", Realm, password)
	if string(key) != string(expected) {
		t.Fatalf("returned key mismatch: got %v, want %v", key, expected)
	}
}

// --- authenticate: different IP fails (core regression test) ---

func TestAuthenticate_DifferentIP_Rejected(t *testing.T) {
	svr := newTestServer()
	svr.allow("user3", "pass", net.ParseIP("192.168.1.100"))

	_, ok := svr.authenticate("user3", Realm, udpAddr("10.0.0.1", 9999))
	if ok {
		t.Fatal("expected authentication to fail when IP does not match")
	}
}

func TestAuthenticate_DifferentIP_Rejected_TCP(t *testing.T) {
	svr := newTestServer()
	svr.allow("user3tcp", "pass", net.ParseIP("192.168.1.100"))

	_, ok := svr.authenticate("user3tcp", Realm, tcpAddr("10.0.0.1", 9999))
	if ok {
		t.Fatal("expected authentication to fail when IP does not match over TCP")
	}
}

// --- authenticate: unknown username fails ---

func TestAuthenticate_UnknownUsername_Rejected(t *testing.T) {
	svr := newTestServer()

	_, ok := svr.authenticate("nonexistent", Realm, udpAddr("192.168.1.1", 1234))
	if ok {
		t.Fatal("expected authentication to fail for unknown username")
	}
}

// --- IPv4-mapped IPv6 handling ---

func TestAuthenticate_IPv4MappedIPv6_MatchesPureIPv4(t *testing.T) {
	svr := newTestServer()
	// Store as pure IPv4
	svr.allow("user4", "pass", net.ParseIP("192.168.1.50"))

	// Authenticate with IPv4-mapped IPv6 representation (::ffff:192.168.1.50)
	mappedIPv6 := net.IPv4(192, 168, 1, 50).To16()
	_, ok := svr.authenticate("user4", Realm, udpAddr(mappedIPv6.String(), 1234))
	if !ok {
		t.Fatalf("expected IPv4-mapped IPv6 %s to match stored IPv4 192.168.1.50 via net.IP.Equal()", mappedIPv6)
	}
}

func TestAuthenticate_PureIPv4_MatchesStoredIPv4MappedIPv6(t *testing.T) {
	svr := newTestServer()
	// Store as IPv4-mapped IPv6
	mappedIPv6 := net.IPv4(10, 0, 0, 1).To16()
	svr.allow("user5", "pass", mappedIPv6)

	// Authenticate with pure IPv4
	_, ok := svr.authenticate("user5", Realm, tcpAddr("10.0.0.1", 5555))
	if !ok {
		t.Fatal("expected pure IPv4 to match stored IPv4-mapped IPv6 via net.IP.Equal()")
	}
}

// --- IPv6 addresses ---

func TestAuthenticate_IPv6_Addresses(t *testing.T) {
	svr := newTestServer()
	ipv6 := net.ParseIP("2001:db8::1")
	svr.allow("user6", "pass", ipv6)

	_, ok := svr.authenticate("user6", Realm, udpAddr("2001:db8::1", 3478))
	if !ok {
		t.Fatal("expected authentication to succeed for matching IPv6")
	}

	_, ok = svr.authenticate("user6", Realm, udpAddr("2001:db8::2", 3478))
	if ok {
		t.Fatal("expected authentication to fail for different IPv6")
	}
}

// --- unknown address type fails safely ---

func TestAuthenticate_UnknownAddrType_Rejected(t *testing.T) {
	svr := newTestServer()
	svr.allow("user7", "pass", net.ParseIP("1.2.3.4"))

	_, ok := svr.authenticate("user7", Realm, customAddr{})
	if ok {
		t.Fatal("expected authentication to fail for unrecognized address type")
	}
}

// --- Disallow removes credentials ---

func TestDisallow_RemovesCredentials(t *testing.T) {
	svr := newTestServer()
	svr.allow("user8", "pass", net.ParseIP("1.2.3.4"))

	// Verify credentials exist
	_, ok := svr.authenticate("user8", Realm, udpAddr("1.2.3.4", 1234))
	if !ok {
		t.Fatal("expected authentication to succeed before Disallow")
	}

	svr.Disallow("user8")

	// Verify credentials are gone
	_, ok = svr.authenticate("user8", Realm, udpAddr("1.2.3.4", 1234))
	if ok {
		t.Fatal("expected authentication to fail after Disallow")
	}
}

// --- Credentials generates and stores valid entries ---

func TestCredentials_GeneratesAndStores(t *testing.T) {
	svr := newTestServer()
	clientIP := net.ParseIP("10.20.30.40")

	username, password := svr.Credentials("sess-host", clientIP)
	if username != "sess-host" {
		t.Fatalf("expected username 'sess-host', got %q", username)
	}
	if password == "" {
		t.Fatal("expected non-empty password")
	}

	// Should authenticate from the same IP
	_, ok := svr.authenticate("sess-host", Realm, udpAddr("10.20.30.40", 5000))
	if !ok {
		t.Fatal("expected authentication to succeed from same IP after Credentials()")
	}

	// Should fail from a different IP
	_, ok = svr.authenticate("sess-host", Realm, udpAddr("99.99.99.99", 5000))
	if ok {
		t.Fatal("expected authentication to fail from different IP after Credentials()")
	}
}

// --- concurrent access safety ---

func TestAuthenticate_ConcurrentAccess(t *testing.T) {
	svr := newTestServer()
	svr.allow("concurrent-user", "pass", net.ParseIP("10.0.0.1"))

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent reads (authenticate)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				svr.authenticate("concurrent-user", Realm, udpAddr("10.0.0.1", j))
			}
		}()
	}

	// Concurrent writes (allow/disallow) interleaved with reads
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := "concurrent-user"
			for j := 0; j < 100; j++ {
				svr.allow(name, "pass", net.ParseIP("10.0.0.1"))
				svr.Disallow(name)
				svr.allow(name, "pass", net.ParseIP("10.0.0.1"))
			}
		}()
	}

	wg.Wait()
}
