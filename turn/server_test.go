package turn

import (
	"bytes"
	"net"
	"testing"

	"github.com/pion/turn/v4"
)

// TestInternalServerAuthenticate verifies that credentials issued by the
// internal TURN server are bound to the client IP they were created for: the
// matching address authenticates, any other address is rejected. The
// "different source IP" case is the regression guard — before the IP check was
// added, authenticate() returned the password for any source address, letting a
// leaked username/password be replayed from another host.
func TestInternalServerAuthenticate(t *testing.T) {
	const username = "room-user"
	const password = "secret-password"
	expectedKey := turn.GenerateAuthKey(username, Realm, password)

	tests := []struct {
		name     string
		storedIP net.IP
		authUser string
		authAddr net.Addr
		wantOK   bool
	}{
		{
			name:     "matching UDP source address",
			storedIP: net.ParseIP("203.0.113.5"),
			authUser: username,
			authAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 51000},
			wantOK:   true,
		},
		{
			name:     "matching TCP source address",
			storedIP: net.ParseIP("203.0.113.5"),
			authUser: username,
			authAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 51000},
			wantOK:   true,
		},
		{
			// The stored IP and the request IP can be in different
			// representations (4-byte vs IPv4-in-IPv6) because they originate
			// from different network layers; net.IP.Equal must treat them as
			// equal.
			name:     "matching address in differing IP representations",
			storedIP: net.ParseIP("203.0.113.5").To4(),
			authUser: username,
			authAddr: &net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.5"), Port: 51000},
			wantOK:   true,
		},
		{
			name:     "matching IPv6 source address",
			storedIP: net.ParseIP("2001:db8::1"),
			authUser: username,
			authAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 51000},
			wantOK:   true,
		},
		{
			name:     "different source IP is rejected",
			storedIP: net.ParseIP("203.0.113.5"),
			authUser: username,
			authAddr: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 51000},
			wantOK:   false,
		},
		{
			name:     "unknown username is rejected",
			storedIP: net.ParseIP("203.0.113.5"),
			authUser: "intruder",
			authAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 51000},
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svr := &InternalServer{lookup: map[string]Entry{}}
			svr.allow(username, password, tt.storedIP)

			key, ok := svr.authenticate(tt.authUser, Realm, tt.authAddr)
			if ok != tt.wantOK {
				t.Fatalf("authenticate(%q, %s) ok = %v, want %v", tt.authUser, tt.authAddr, ok, tt.wantOK)
			}
			if tt.wantOK && !bytes.Equal(key, expectedKey) {
				t.Fatalf("authenticate() returned key %v, want %v", key, expectedKey)
			}
			if !tt.wantOK && key != nil {
				t.Fatalf("authenticate() returned non-nil key %v on rejection", key)
			}
		})
	}
}

// TestInternalServerDisallowRevokesCredentials confirms that revoked
// credentials no longer authenticate even from the original client IP.
func TestInternalServerDisallowRevokesCredentials(t *testing.T) {
	svr := &InternalServer{lookup: map[string]Entry{}}
	ip := net.ParseIP("203.0.113.5")
	username, _ := svr.Credentials("room-user", ip)

	if _, ok := svr.authenticate(username, Realm, &net.UDPAddr{IP: ip, Port: 51000}); !ok {
		t.Fatalf("authenticate() before Disallow = false, want true")
	}

	svr.Disallow(username)

	if _, ok := svr.authenticate(username, Realm, &net.UDPAddr{IP: ip, Port: 51000}); ok {
		t.Fatalf("authenticate() after Disallow = true, want false")
	}
}
