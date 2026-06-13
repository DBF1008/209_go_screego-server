package ws

import (
	"net"
	"strings"
	"testing"

	"github.com/rs/xid"
	"github.com/screego/server/config"
	"github.com/screego/server/config/ipdns"
	"github.com/screego/server/ws/outgoing"
)

// --- test helpers ---

// noopTurnServer is a minimal turn.Server implementation for unit tests that
// never exercise real TURN credential generation.
type noopTurnServer struct{}

func (noopTurnServer) Credentials(id string, addr net.IP) (string, string) { return id, "pw" }
func (noopTurnServer) Disallow(username string)                             {}

// testRooms builds a *Rooms with the given auth mode, a deterministic random
// source, and stub providers that are sufficient for unit tests.
func testRooms(authMode string) *Rooms {
	return &Rooms{
		Rooms:      map[string]*Room{},
		connected:  map[xid.ID]string{},
		turnServer: noopTurnServer{},
		config: config.Config{
			AuthMode:       authMode,
			TurnIPProvider: &ipdns.Static{V4: net.IPv4(127, 0, 0, 1)},
		},
	}
}

// connectClient simulates the Connected event so that the "already connected"
// guard in Create / Join sees the client as a live WebSocket connection.
func connectClient(r *Rooms, authed bool) ClientInfo {
	c := ClientInfo{
		ID:                xid.New(),
		Authenticated:     authed,
		AuthenticatedUser: "testuser",
		Write:             make(chan outgoing.Message, 10),
		Addr:              net.IPv4(127, 0, 0, 1),
	}
	r.connected[c.ID] = ""
	return c
}

// createRoom is a shortcut that creates a room via the Create handler (as an
// authenticated owner) so that subsequent tests can exercise Join paths.
func createRoom(r *Rooms, id string, mode ConnectionMode) {
	owner := connectClient(r, true)
	create := &Create{ID: id, Mode: mode, CloseOnOwnerLeave: true, UserName: "owner"}
	if err := create.Execute(r, owner); err != nil {
		panic("test helper createRoom: " + err.Error())
	}
}

func requireError(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected error containing %q, got %q", substr, err.Error())
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- checkAuth unit tests ---

func TestCheckAuth_none(t *testing.T) {
	r := testRooms(config.AuthModeNone)
	if err := checkAuth(r, ConnectionTURN, false); err != nil {
		t.Fatalf("AuthModeNone should never require login, got: %v", err)
	}
}

func TestCheckAuth_all_unauthenticated(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	requireError(t, checkAuth(r, ConnectionTURN, false), "you need to login")
}

func TestCheckAuth_all_authenticated(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	requireNoError(t, checkAuth(r, ConnectionTURN, true))
}

func TestCheckAuth_turn_turnMode_unauthenticated(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	requireError(t, checkAuth(r, ConnectionTURN, false), "you need to login")
}

func TestCheckAuth_turn_stunMode_unauthenticated(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	requireNoError(t, checkAuth(r, ConnectionSTUN, false))
}

func TestCheckAuth_turn_localMode_unauthenticated(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	requireNoError(t, checkAuth(r, ConnectionLocal, false))
}

func TestCheckAuth_turn_turnMode_authenticated(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	requireNoError(t, checkAuth(r, ConnectionTURN, true))
}

func TestCheckAuth_invalidMode(t *testing.T) {
	r := testRooms("bogus")
	requireError(t, checkAuth(r, ConnectionTURN, true), "invalid authmode")
}

// --- Create auth enforcement (regression) ---

func TestCreate_authAll_unauthenticated_rejected(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	c := connectClient(r, false)
	err := (&Create{ID: "r1", Mode: ConnectionTURN, UserName: "x"}).Execute(r, c)
	requireError(t, err, "you need to login")
	if _, ok := r.Rooms["r1"]; ok {
		t.Fatal("room should not have been created")
	}
}

func TestCreate_authAll_authenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	c := connectClient(r, true)
	requireNoError(t, (&Create{ID: "r1", Mode: ConnectionTURN, UserName: "x"}).Execute(r, c))
	if _, ok := r.Rooms["r1"]; !ok {
		t.Fatal("room should have been created")
	}
}

func TestCreate_authTurn_turnRoom_unauthenticated_rejected(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	c := connectClient(r, false)
	err := (&Create{ID: "r1", Mode: ConnectionTURN, UserName: "x"}).Execute(r, c)
	requireError(t, err, "you need to login")
}

func TestCreate_authTurn_stunRoom_unauthenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	c := connectClient(r, false)
	requireNoError(t, (&Create{ID: "r1", Mode: ConnectionSTUN, UserName: "x"}).Execute(r, c))
}

func TestCreate_authNone_unauthenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeNone)
	c := connectClient(r, false)
	requireNoError(t, (&Create{ID: "r1", Mode: ConnectionTURN, UserName: "x"}).Execute(r, c))
}

// --- Join auth enforcement (the core fix) ---

func TestJoin_authAll_unauthenticated_rejected(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	createRoom(r, "r1", ConnectionTURN)

	joiner := connectClient(r, false)
	err := (&Join{ID: "r1", UserName: "intruder"}).Execute(r, joiner)
	requireError(t, err, "you need to login")

	// Verify the user was NOT added to the room.
	if _, ok := r.Rooms["r1"].Users[joiner.ID]; ok {
		t.Fatal("unauthenticated user should not have been added to room")
	}
}

func TestJoin_authAll_authenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	createRoom(r, "r1", ConnectionTURN)

	joiner := connectClient(r, true)
	requireNoError(t, (&Join{ID: "r1", UserName: "user"}).Execute(r, joiner))

	if _, ok := r.Rooms["r1"].Users[joiner.ID]; !ok {
		t.Fatal("authenticated user should have been added to room")
	}
}

func TestJoin_authTurn_turnRoom_unauthenticated_rejected(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	createRoom(r, "r1", ConnectionTURN)

	joiner := connectClient(r, false)
	err := (&Join{ID: "r1", UserName: "intruder"}).Execute(r, joiner)
	requireError(t, err, "you need to login")

	if _, ok := r.Rooms["r1"].Users[joiner.ID]; ok {
		t.Fatal("unauthenticated user should not have been added to TURN room")
	}
}

func TestJoin_authTurn_stunRoom_unauthenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	createRoom(r, "r1", ConnectionSTUN)

	joiner := connectClient(r, false)
	requireNoError(t, (&Join{ID: "r1", UserName: "guest"}).Execute(r, joiner))

	if _, ok := r.Rooms["r1"].Users[joiner.ID]; !ok {
		t.Fatal("unauthenticated user should have been added to STUN room in turn mode")
	}
}

func TestJoin_authTurn_localRoom_unauthenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	createRoom(r, "r1", ConnectionLocal)

	joiner := connectClient(r, false)
	requireNoError(t, (&Join{ID: "r1", UserName: "guest"}).Execute(r, joiner))

	if _, ok := r.Rooms["r1"].Users[joiner.ID]; !ok {
		t.Fatal("unauthenticated user should have been added to Local room in turn mode")
	}
}

func TestJoin_authNone_unauthenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeNone)
	createRoom(r, "r1", ConnectionTURN)

	joiner := connectClient(r, false)
	requireNoError(t, (&Join{ID: "r1", UserName: "anyone"}).Execute(r, joiner))

	if _, ok := r.Rooms["r1"].Users[joiner.ID]; !ok {
		t.Fatal("user should have been added in none mode")
	}
}

// --- JoinIfExist delegation path (regression) ---
//
// Create{JoinIfExist: true} delegates to Join.Execute when the room already
// exists. This was the original attack vector: the Create auth check was
// bypassed because Join had no auth logic.

func TestCreate_joinIfExist_authAll_unauthenticated_rejected(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	createRoom(r, "r1", ConnectionTURN)

	intruder := connectClient(r, false)
	err := (&Create{ID: "r1", JoinIfExist: true, UserName: "intruder"}).Execute(r, intruder)
	requireError(t, err, "you need to login")

	if _, ok := r.Rooms["r1"].Users[intruder.ID]; ok {
		t.Fatal("unauthenticated user should not join via JoinIfExist in all mode")
	}
}

func TestCreate_joinIfExist_authTurn_turnRoom_unauthenticated_rejected(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	createRoom(r, "r1", ConnectionTURN)

	intruder := connectClient(r, false)
	err := (&Create{ID: "r1", JoinIfExist: true, UserName: "intruder"}).Execute(r, intruder)
	requireError(t, err, "you need to login")

	if _, ok := r.Rooms["r1"].Users[intruder.ID]; ok {
		t.Fatal("unauthenticated user should not join TURN room via JoinIfExist")
	}
}

func TestCreate_joinIfExist_authTurn_stunRoom_unauthenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeTurn)
	createRoom(r, "r1", ConnectionSTUN)

	guest := connectClient(r, false)
	requireNoError(t, (&Create{ID: "r1", JoinIfExist: true, UserName: "guest"}).Execute(r, guest))

	if _, ok := r.Rooms["r1"].Users[guest.ID]; !ok {
		t.Fatal("unauthenticated user should join STUN room via JoinIfExist in turn mode")
	}
}

func TestCreate_joinIfExist_authAll_authenticated_allowed(t *testing.T) {
	r := testRooms(config.AuthModeAll)
	createRoom(r, "r1", ConnectionTURN)

	user := connectClient(r, true)
	requireNoError(t, (&Create{ID: "r1", JoinIfExist: true, UserName: "user"}).Execute(r, user))

	if _, ok := r.Rooms["r1"].Users[user.ID]; !ok {
		t.Fatal("authenticated user should join via JoinIfExist in all mode")
	}
}

// --- Pre-condition checks still work ---

func TestJoin_nonexistentRoom(t *testing.T) {
	r := testRooms(config.AuthModeNone)
	c := connectClient(r, false)
	err := (&Join{ID: "nope"}).Execute(r, c)
	requireError(t, err, "does not exist")
}

func TestJoin_alreadyInRoom(t *testing.T) {
	r := testRooms(config.AuthModeNone)
	createRoom(r, "r1", ConnectionTURN)

	// Connect a second client and put them in a room first.
	c := connectClient(r, false)
	r.connected[c.ID] = "other-room"

	err := (&Join{ID: "r1"}).Execute(r, c)
	requireError(t, err, "already in one")
}

func TestCreate_alreadyInRoom(t *testing.T) {
	r := testRooms(config.AuthModeNone)
	c := connectClient(r, false)
	r.connected[c.ID] = "some-room"

	err := (&Create{ID: "new"}).Execute(r, c)
	requireError(t, err, "already in one")
}
