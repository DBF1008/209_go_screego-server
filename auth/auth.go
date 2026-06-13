package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type Users struct {
	Lookup         map[string]string
	store          sessions.Store
	sessionTimeout int

	// sessions is the authoritative, server-side record of which sessions are
	// currently logged in. The session cookie only carries an opaque id (sid);
	// a request (or a long-lived WebSocket) is authenticated only while that id
	// is still present and unexpired here. This is what lets Logout and session
	// expiry take effect immediately for connections that were established
	// earlier — the cookie store alone cannot, because it keeps no server state
	// and a WebSocket never re-sends its cookie after the handshake.
	mu       sync.Mutex
	sessions map[string]sessionEntry
}

// sessionEntry is a single live session. A zero expires means the session
// never expires on its own (the deployment configured no session timeout) and
// only ends on explicit logout.
type sessionEntry struct {
	user    string
	expires time.Time
}

type UserPW struct {
	Name string
	Pass string
}

func read(r io.Reader) ([]UserPW, error) {
	reader := csv.NewReader(r)
	reader.Comma = ':'
	reader.Comment = '#'
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	result := []UserPW{}
	for _, record := range records {
		if len(record) != 2 {
			return nil, errors.New("malformed users file")
		}
		result = append(result, UserPW{Name: record[0], Pass: record[1]})
	}
	return result, nil
}

func ReadPasswordsFile(path string, secret []byte, sessionTimeout int) (*Users, error) {
	users := &Users{
		Lookup:         map[string]string{},
		sessionTimeout: sessionTimeout,
		store:          sessions.NewCookieStore(secret),
		sessions:       map[string]sessionEntry{},
	}
	if path == "" {
		log.Info().Msg("Users file not specified")
		return users, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return users, err
	}
	defer file.Close()
	userPws, err := read(file)
	if err != nil {
		return users, err
	}

	for _, record := range userPws {
		users.Lookup[record.Name] = record.Pass
	}
	log.Info().Int("amount", len(users.Lookup)).Msg("Loaded Users")
	return users, nil
}

type Response struct {
	Message string `json:"message"`
}

// CurrentUser reports the user associated with the request's session and
// whether that session is currently logged in. It is the live check: a request
// whose session has been logged out or has expired is reported as the guest,
// even if it still carries a previously-valid cookie.
func (u *Users) CurrentUser(r *http.Request) (string, bool) {
	return u.SessionUser(u.SessionID(r))
}

// SessionID returns the opaque session id stored in the request's signed
// session cookie, or "" when there is none (or the cookie itself is invalid or
// expired). It does not consult the server-side registry; callers pair it with
// SessionUser to determine whether the session is still live.
func (u *Users) SessionID(r *http.Request) string {
	s, _ := u.store.Get(r, "user")
	sid, _ := s.Values["sid"].(string)
	return sid
}

// SessionUser resolves a session id against the server-side registry. ok is
// false when the id is empty, unknown (never issued, or revoked by logout), or
// expired. Expired entries are dropped lazily on lookup. This is the single
// source of truth consulted on every privileged action, including by
// already-connected WebSockets that re-validate their handshake-time id.
func (u *Users) SessionUser(sid string) (string, bool) {
	if sid == "" {
		return "guest", false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	entry, ok := u.sessions[sid]
	if !ok {
		return "guest", false
	}
	if !entry.expires.IsZero() && !entry.expires.After(time.Now()) {
		delete(u.sessions, sid)
		return "guest", false
	}
	return entry.user, true
}

func (u *Users) Logout(w http.ResponseWriter, r *http.Request) {
	// Revoke the server-side session first so that any connection still using
	// this id (e.g. a long-lived WebSocket) loses access immediately, then
	// clear the cookie on the client.
	session, _ := u.store.Get(r, "user")
	if sid, ok := session.Values["sid"].(string); ok {
		u.revokeSession(sid)
	}
	session.Values = map[interface{}]interface{}{}
	session.Options = &sessions.Options{MaxAge: -1, Path: "/"}
	if err := u.store.Save(r, w, session); err != nil {
		w.WriteHeader(500)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: err.Error(),
		})
		return
	}
	w.WriteHeader(200)
}

func (u *Users) Authenticate(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	pass := r.FormValue("pass")

	if !u.Validate(user, pass) {
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: "could not authenticate",
		})
		return
	}

	sid, err := newSessionID()
	if err != nil {
		w.WriteHeader(500)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: err.Error(),
		})
		return
	}

	session := sessions.NewSession(u.store, "user")
	session.IsNew = true
	session.Options = &sessions.Options{MaxAge: u.sessionTimeout, Path: "/"}
	session.Values["user"] = user
	session.Values["sid"] = sid
	if err := u.store.Save(r, w, session); err != nil {
		w.WriteHeader(500)
		_ = json.NewEncoder(w).Encode(&Response{
			Message: err.Error(),
		})
		return
	}

	u.registerSession(sid, user)

	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(&Response{
		Message: "authenticated",
	})
}

// newSessionID returns a cryptographically random, URL-safe session id.
func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// registerSession records a freshly issued session as live. When a session
// timeout is configured the entry is given a matching expiry; otherwise it
// lives until logout. Expired entries are swept opportunistically here so the
// registry does not grow without bound across many short-lived logins.
func (u *Users) registerSession(sid, user string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.purgeExpiredLocked()
	var expires time.Time
	if u.sessionTimeout > 0 {
		expires = time.Now().Add(time.Duration(u.sessionTimeout) * time.Second)
	}
	u.sessions[sid] = sessionEntry{user: user, expires: expires}
}

// revokeSession ends a session immediately. Used by logout.
func (u *Users) revokeSession(sid string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.sessions, sid)
}

// purgeExpiredLocked removes timed-out entries. Callers must hold u.mu.
func (u *Users) purgeExpiredLocked() {
	now := time.Now()
	for sid, entry := range u.sessions {
		if !entry.expires.IsZero() && !entry.expires.After(now) {
			delete(u.sessions, sid)
		}
	}
}

func (u *Users) Validate(user, password string) bool {
	realPassword, exists := u.Lookup[user]
	return exists && bcrypt.CompareHashAndPassword([]byte(realPassword), []byte(password)) == nil
}
