package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// newTestUsers builds a *Users with a single account (alice/secret) and the
// given session timeout (seconds; 0 = no timeout).
func newTestUsers(t *testing.T, sessionTimeout int) *Users {
	t.Helper()
	u, err := ReadPasswordsFile("", testSecret, sessionTimeout)
	if err != nil {
		t.Fatalf("ReadPasswordsFile: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	u.Lookup["alice"] = string(hash)
	return u
}

// login performs an Authenticate round-trip and returns the issued session
// cookie. It fails the test if authentication did not succeed.
func login(t *testing.T, u *Users, user, pass string) *http.Cookie {
	t.Helper()
	form := url.Values{"user": {user}, "pass": {pass}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	u.Authenticate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "user" {
			return c
		}
	}
	t.Fatal("login: no session cookie was set")
	return nil
}

// withCookie builds a request that carries the given session cookie, simulating
// a client (or a long-lived WebSocket handshake) presenting it.
func withCookie(c *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if c != nil {
		req.AddCookie(c)
	}
	return req
}

func TestAuthenticate_setsLoggedInSession(t *testing.T) {
	u := newTestUsers(t, 0)
	cookie := login(t, u, "alice", "secret")

	user, ok := u.CurrentUser(withCookie(cookie))
	if !ok || user != "alice" {
		t.Fatalf("expected (alice, true), got (%q, %v)", user, ok)
	}
}

func TestAuthenticate_wrongPassword(t *testing.T) {
	u := newTestUsers(t, 0)
	form := url.Values{"user": {"alice"}, "pass": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	u.Authenticate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if len(u.sessions) != 0 {
		t.Fatalf("a failed login must not register a session, got %d", len(u.sessions))
	}
}

func TestCurrentUser_noCookie_guest(t *testing.T) {
	u := newTestUsers(t, 0)
	user, ok := u.CurrentUser(withCookie(nil))
	if ok || user != "guest" {
		t.Fatalf("expected (guest, false), got (%q, %v)", user, ok)
	}
}

// TestLogout_revokesSession is the core regression for logout: a client that
// keeps presenting its *original* (pre-logout) cookie — exactly what an
// already-upgraded WebSocket does — must be treated as logged out, because the
// server-side session was revoked.
func TestLogout_revokesSession(t *testing.T) {
	u := newTestUsers(t, 0)
	cookie := login(t, u, "alice", "secret")

	if _, ok := u.CurrentUser(withCookie(cookie)); !ok {
		t.Fatal("precondition: should be logged in right after login")
	}

	u.Logout(httptest.NewRecorder(), withCookie(cookie))

	// The stale connection still holds the same cookie, yet must now be guest.
	if user, ok := u.CurrentUser(withCookie(cookie)); ok || user != "guest" {
		t.Fatalf("after logout expected (guest, false), got (%q, %v)", user, ok)
	}
	if len(u.sessions) != 0 {
		t.Fatalf("logout should leave no live sessions, got %d", len(u.sessions))
	}
}

// TestLogout_doesNotAffectOtherSessions guards against logout revoking more
// than the one session it was given (e.g. accidentally clearing the whole map).
func TestLogout_doesNotAffectOtherSessions(t *testing.T) {
	u := newTestUsers(t, 0)
	c1 := login(t, u, "alice", "secret")
	c2 := login(t, u, "alice", "secret")

	u.Logout(httptest.NewRecorder(), withCookie(c1))

	if _, ok := u.CurrentUser(withCookie(c1)); ok {
		t.Fatal("session 1 should be revoked")
	}
	if _, ok := u.CurrentUser(withCookie(c2)); !ok {
		t.Fatal("session 2 must remain valid after another session logs out")
	}
}

// TestSessionExpiry_revokesSession verifies the time dimension: once a session
// passes its expiry it is no longer accepted (and is cleaned up lazily), even
// while the cookie itself is still presented.
func TestSessionExpiry_revokesSession(t *testing.T) {
	u := newTestUsers(t, 3600)
	cookie := login(t, u, "alice", "secret")

	sid := u.SessionID(withCookie(cookie))
	if sid == "" {
		t.Fatal("expected a session id in the cookie")
	}

	// Force the entry to be expired.
	u.mu.Lock()
	entry := u.sessions[sid]
	entry.expires = time.Now().Add(-time.Second)
	u.sessions[sid] = entry
	u.mu.Unlock()

	if user, ok := u.SessionUser(sid); ok || user != "guest" {
		t.Fatalf("expired session: expected (guest, false), got (%q, %v)", user, ok)
	}
	if user, ok := u.CurrentUser(withCookie(cookie)); ok || user != "guest" {
		t.Fatalf("expired session via CurrentUser: expected (guest, false), got (%q, %v)", user, ok)
	}
	if _, present := u.sessions[sid]; present {
		t.Fatal("expired entry should have been dropped on lookup")
	}
}

func TestSessionUser_unknownAndEmpty(t *testing.T) {
	u := newTestUsers(t, 0)
	if user, ok := u.SessionUser("does-not-exist"); ok || user != "guest" {
		t.Fatalf("unknown sid: expected (guest, false), got (%q, %v)", user, ok)
	}
	if user, ok := u.SessionUser(""); ok || user != "guest" {
		t.Fatalf("empty sid: expected (guest, false), got (%q, %v)", user, ok)
	}
}

// TestRegisterSession_purgesExpired ensures the registry does not accumulate
// timed-out entries across logins.
func TestRegisterSession_purgesExpired(t *testing.T) {
	u := newTestUsers(t, 3600)

	u.mu.Lock()
	u.sessions["stale"] = sessionEntry{user: "ghost", expires: time.Now().Add(-time.Hour)}
	u.mu.Unlock()

	// A fresh login triggers an opportunistic purge.
	login(t, u, "alice", "secret")

	u.mu.Lock()
	_, stalePresent := u.sessions["stale"]
	live := len(u.sessions)
	u.mu.Unlock()

	if stalePresent {
		t.Fatal("stale entry should have been purged by registerSession")
	}
	if live != 1 {
		t.Fatalf("expected exactly the one live session, got %d", live)
	}
}
