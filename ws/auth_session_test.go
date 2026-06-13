package ws

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/xid"
	"github.com/screego/server/auth"
	"github.com/screego/server/config"
	"github.com/screego/server/ws/outgoing"
	"golang.org/x/crypto/bcrypt"
)

// These tests cover the temporal dimension of authentication: a WebSocket is
// authenticated once at handshake, but its privileges must follow the live
// session — logging out or letting the session expire has to revoke a socket
// that is already connected, not just future HTTP requests.

var wsTestSecret = []byte("0123456789abcdef0123456789abcdef")

// loginAlice builds an auth.Users with a single account and returns it together
// with the session cookie issued by a successful login.
func loginAlice(t *testing.T, sessionTimeout int) (*auth.Users, *http.Cookie) {
	t.Helper()
	users, err := auth.ReadPasswordsFile("", wsTestSecret, sessionTimeout)
	if err != nil {
		t.Fatalf("ReadPasswordsFile: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	users.Lookup["alice"] = string(hash)

	form := url.Values{"user": {"alice"}, "pass": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	users.Authenticate(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "user" {
			return users, c
		}
	}
	t.Fatal("login: no session cookie set")
	return nil, nil
}

func reqWithCookie(c *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	return req
}

// staleClient mimics a connected WebSocket whose only auth state is the session
// id captured at handshake (Authenticated/AuthenticatedUser are intentionally
// left zero — refreshAuth is responsible for deriving them from the live store).
func staleClient(r *Rooms, sid string) ClientInfo {
	c := ClientInfo{
		ID:            xid.New(),
		AuthSessionID: sid,
		Write:         make(chan outgoing.Message, 10),
		Addr:          net.IPv4(127, 0, 0, 1),
	}
	r.connected[c.ID] = ""
	return c
}

func TestRefreshAuth_validSession(t *testing.T) {
	users, cookie := loginAlice(t, 0)
	sid := users.SessionID(reqWithCookie(cookie))

	r := testRooms(config.AuthModeAll)
	r.users = users

	got := r.refreshAuth(ClientInfo{AuthSessionID: sid})
	if !got.Authenticated || got.AuthenticatedUser != "alice" {
		t.Fatalf("expected authenticated alice, got authenticated=%v user=%q", got.Authenticated, got.AuthenticatedUser)
	}
}

func TestRefreshAuth_revokedAfterLogout(t *testing.T) {
	users, cookie := loginAlice(t, 0)
	sid := users.SessionID(reqWithCookie(cookie))

	r := testRooms(config.AuthModeAll)
	r.users = users

	if got := r.refreshAuth(ClientInfo{AuthSessionID: sid}); !got.Authenticated {
		t.Fatal("precondition: session should be valid before logout")
	}

	users.Logout(httptest.NewRecorder(), reqWithCookie(cookie))

	got := r.refreshAuth(ClientInfo{Authenticated: true, AuthenticatedUser: "alice", AuthSessionID: sid})
	if got.Authenticated || got.AuthenticatedUser != "" {
		t.Fatalf("after logout expected guest, got authenticated=%v user=%q", got.Authenticated, got.AuthenticatedUser)
	}
}

func TestRefreshAuth_unknownSessionIsGuest(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	r.users, _ = loginAlice(t, 0) // valid users, but an id we never issued

	got := r.refreshAuth(ClientInfo{Authenticated: true, AuthenticatedUser: "alice", AuthSessionID: "bogus"})
	if got.Authenticated || got.AuthenticatedUser != "" {
		t.Fatalf("unknown session should be guest, got authenticated=%v user=%q", got.Authenticated, got.AuthenticatedUser)
	}
}

func TestRefreshAuth_nilUsers_unchanged(t *testing.T) {
	r := &Rooms{} // no auth.Users wired (mirrors handlers that build Rooms bare)
	in := ClientInfo{Authenticated: true, AuthenticatedUser: "x", AuthSessionID: "sid"}
	got := r.refreshAuth(in)
	if got.Authenticated != in.Authenticated || got.AuthenticatedUser != in.AuthenticatedUser {
		t.Fatalf("with nil users, auth must be left untouched, got %+v", got)
	}
}

// TestStaleConnection_authAll_createRejectedAfterLogout is the headline
// regression: a socket that was authenticated at handshake must no longer be
// able to create a (TURN) room once its session has been logged out.
func TestStaleConnection_authAll_createRejectedAfterLogout(t *testing.T) {
	users, cookie := loginAlice(t, 0)
	sid := users.SessionID(reqWithCookie(cookie))

	r := testRooms(config.AuthModeAll)
	r.users = users
	client := staleClient(r, sid)

	users.Logout(httptest.NewRecorder(), reqWithCookie(cookie))

	stale := r.refreshAuth(client)
	err := (&Create{ID: "r1", Mode: ConnectionTURN, UserName: "x"}).Execute(r, stale)
	requireError(t, err, "you need to login")
	if _, ok := r.Rooms["r1"]; ok {
		t.Fatal("a logged-out socket must not be able to create a room")
	}
}

// TestStaleConnection_authTurn_joinRejectedAfterLogout covers the TURN-room
// capability leak via Join: after logout the socket can no longer join a
// protected TURN room (and therefore can no longer obtain TURN credentials).
func TestStaleConnection_authTurn_joinRejectedAfterLogout(t *testing.T) {
	users, cookie := loginAlice(t, 0)
	sid := users.SessionID(reqWithCookie(cookie))

	r := testRooms(config.AuthModeTurn)
	r.users = users
	createRoom(r, "r1", ConnectionTURN)

	users.Logout(httptest.NewRecorder(), reqWithCookie(cookie))

	client := staleClient(r, sid)
	stale := r.refreshAuth(client)
	err := (&Join{ID: "r1", UserName: "intruder"}).Execute(r, stale)
	requireError(t, err, "you need to login")
	if _, ok := r.Rooms["r1"].Users[client.ID]; ok {
		t.Fatal("a logged-out socket must not be able to join a TURN room")
	}
}

// TestStaleConnection_authAll_createAllowedWhileLoggedIn is the positive
// control: a still-valid session keeps working through the refresh path, and
// the authenticated user name is applied.
func TestStaleConnection_authAll_createAllowedWhileLoggedIn(t *testing.T) {
	users, cookie := loginAlice(t, 0)
	sid := users.SessionID(reqWithCookie(cookie))

	r := testRooms(config.AuthModeAll)
	r.users = users
	client := staleClient(r, sid)

	live := r.refreshAuth(client)
	requireNoError(t, (&Create{ID: "r1", Mode: ConnectionTURN, UserName: "ignored"}).Execute(r, live))

	room, ok := r.Rooms["r1"]
	if !ok {
		t.Fatal("authenticated socket should be able to create a room")
	}
	if room.Users[client.ID].Name != "alice" {
		t.Fatalf("expected owner name from session (alice), got %q", room.Users[client.ID].Name)
	}
}
