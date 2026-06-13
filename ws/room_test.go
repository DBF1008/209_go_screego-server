package ws

import (
	"net"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/screego/server/config"
	"github.com/screego/server/config/ipdns"
	"github.com/screego/server/ws/outgoing"
)

// ---------------------------------------------------------------------------
// Mock TURN server — records all Credentials / Disallow calls for assertion.
// ---------------------------------------------------------------------------

type mockTurnServer struct {
	disallowed []string
}

func (m *mockTurnServer) Credentials(id string, _ net.IP) (string, string) {
	return id, "test-password"
}

func (m *mockTurnServer) Disallow(username string) {
	m.disallowed = append(m.disallowed, username)
}

// ---------------------------------------------------------------------------
// Test context — builds a Rooms instance with controllable state and
// buffered write channels for collecting outgoing messages.
// ---------------------------------------------------------------------------

type testContext struct {
	rooms  *Rooms
	turn   *mockTurnServer
	writes map[xid.ID]chan outgoing.Message
}

func newTestContext() *testContext {
	mock := &mockTurnServer{}
	return &testContext{
		rooms: &Rooms{
			turnServer: mock,
			Rooms:      map[string]*Room{},
			connected:  map[xid.ID]string{},
			config: config.Config{
				AuthMode:       config.AuthModeNone,
				TurnIPProvider: &ipdns.Static{V4: net.ParseIP("1.2.3.4")},
				TurnPort:       "3478",
			},
		},
		turn:   mock,
		writes: map[xid.ID]chan outgoing.Message{},
	}
}

func (tc *testContext) addRoom(id string, closeOnOwnerLeave bool, mode ConnectionMode) {
	tc.rooms.Rooms[id] = &Room{
		ID:                id,
		CloseOnOwnerLeave: closeOnOwnerLeave,
		Mode:              mode,
		Users:             map[xid.ID]*User{},
		Sessions:          map[xid.ID]*RoomSession{},
	}
}

// addUser inserts a user into the room and registers them in the connected
// map. The user's write channel is buffered (size 10) so that cleanup code
// can send messages without blocking during tests.
func (tc *testContext) addUser(roomID string, id xid.ID, owner, streaming bool) {
	ch := make(chan outgoing.Message, 10)
	tc.writes[id] = ch
	tc.rooms.Rooms[roomID].Users[id] = &User{
		ID:        id,
		Name:      "user-" + id.String()[:4],
		Owner:     owner,
		Streaming: streaming,
		Addr:      net.ParseIP("127.0.0.1"),
		_write:    ch,
	}
	tc.rooms.connected[id] = roomID
}

// addSession inserts a pre-built session into the room. No TURN credentials
// are created (appropriate for STUN/local mode tests).
func (tc *testContext) addSession(roomID string, sessID xid.ID, host, client xid.ID) {
	tc.rooms.Rooms[roomID].Sessions[sessID] = &RoomSession{
		Host:   host,
		Client: client,
	}
}

// collectMessages drains the user's write channel with a short timeout.
func (tc *testContext) collectMessages(userID xid.ID) []outgoing.Message {
	ch, ok := tc.writes[userID]
	if !ok {
		return nil
	}
	var msgs []outgoing.Message
	for {
		select {
		case msg := <-ch:
			msgs = append(msgs, msg)
		case <-time.After(100 * time.Millisecond):
			return msgs
		}
	}
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

func countEndShare(msgs []outgoing.Message) int {
	n := 0
	for _, m := range msgs {
		if _, ok := m.(outgoing.EndShare); ok {
			n++
		}
	}
	return n
}

func countCloseWriter(msgs []outgoing.Message) int {
	n := 0
	for _, m := range msgs {
		if _, ok := m.(outgoing.CloseWriter); ok {
			n++
		}
	}
	return n
}

func countRoomMsg(msgs []outgoing.Message) int {
	n := 0
	for _, m := range msgs {
		if _, ok := m.(outgoing.Room); ok {
			n++
		}
	}
	return n
}

func hasEndShareForSession(msgs []outgoing.Message, sessID xid.ID) bool {
	for _, m := range msgs {
		if es, ok := m.(outgoing.EndShare); ok {
			if xid.ID(es) == sessID {
				return true
			}
		}
	}
	return false
}

// hasUserSorted checks whether a Room message contains users in the expected
// sorted order (owner first, then streaming, then alphabetical by name).
func hasUserSorted(msgs []outgoing.Message, expectedOrder []xid.ID) bool {
	for _, m := range msgs {
		if rm, ok := m.(outgoing.Room); ok {
			if len(rm.Users) != len(expectedOrder) {
				return false
			}
			for i, id := range expectedOrder {
				if rm.Users[i].ID != id {
					return false
				}
			}
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Room.removeUser tests
// ---------------------------------------------------------------------------

func TestRoomRemoveUser_Present(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionSTUN)
	userID := xid.New()
	tc.addUser("r1", userID, false, false)

	room := tc.rooms.Rooms["r1"]
	ok := room.removeUser(userID)

	if !ok {
		t.Fatal("expected removeUser to return true for existing user")
	}
	if _, exists := room.Users[userID]; exists {
		t.Fatal("user should be removed from Users map")
	}
	if len(room.Users) != 0 {
		t.Fatalf("expected 0 users, got %d", len(room.Users))
	}
}

func TestRoomRemoveUser_NotPresent(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionSTUN)

	room := tc.rooms.Rooms["r1"]
	ok := room.removeUser(xid.New())

	if ok {
		t.Fatal("expected removeUser to return false for non-existing user")
	}
}

// ---------------------------------------------------------------------------
// Room.closeUserSessions tests
// ---------------------------------------------------------------------------

func TestCloseUserSessions_MultipleRoles(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionTURN)

	leavingUser := xid.New()
	peerA := xid.New()
	peerB := xid.New()
	peerC := xid.New()
	tc.addUser("r1", leavingUser, false, true)
	tc.addUser("r1", peerA, false, false)
	tc.addUser("r1", peerB, false, false)
	tc.addUser("r1", peerC, false, false)

	// leavingUser is HOST for 2 sessions, CLIENT for 1 session.
	sess1 := xid.New() // host=leavingUser, client=peerA
	sess2 := xid.New() // host=leavingUser, client=peerB
	sess3 := xid.New() // host=peerC, client=leavingUser
	tc.addSession("r1", sess1, leavingUser, peerA)
	tc.addSession("r1", sess2, leavingUser, peerB)
	tc.addSession("r1", sess3, peerC, leavingUser)

	room := tc.rooms.Rooms["r1"]
	closed := room.closeUserSessions(tc.rooms, leavingUser)

	if len(closed) != 3 {
		t.Fatalf("expected 3 closed sessions, got %d", len(closed))
	}
	if len(room.Sessions) != 0 {
		t.Fatalf("expected 0 remaining sessions, got %d", len(room.Sessions))
	}

	// peerA (client of sess1) should receive EndShare
	if !hasEndShareForSession(tc.collectMessages(peerA), sess1) {
		t.Error("peerA should receive EndShare for sess1")
	}
	// peerB (client of sess2) should receive EndShare
	if !hasEndShareForSession(tc.collectMessages(peerB), sess2) {
		t.Error("peerB should receive EndShare for sess2")
	}
	// peerC (host of sess3) should receive EndShare
	if !hasEndShareForSession(tc.collectMessages(peerC), sess3) {
		t.Error("peerC should receive EndShare for sess3")
	}

	// 3 sessions × 2 (host + client) = 6 TURN credential revocations
	if len(tc.turn.disallowed) != 6 {
		t.Errorf("expected 6 TURN Disallow calls, got %d: %v", len(tc.turn.disallowed), tc.turn.disallowed)
	}
}

// ---------------------------------------------------------------------------
// Room.closeHostSessions tests (used by StopShare)
// ---------------------------------------------------------------------------

func TestCloseHostSessions_StopShare(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionTURN)

	hostUser := xid.New()
	clientA := xid.New()
	clientB := xid.New()
	upstream := xid.New() // someone else sharing TO hostUser
	tc.addUser("r1", hostUser, false, true)
	tc.addUser("r1", clientA, false, false)
	tc.addUser("r1", clientB, false, false)
	tc.addUser("r1", upstream, false, true)

	// hostUser is HOST for 2 sessions
	hostSess1 := xid.New()
	hostSess2 := xid.New()
	tc.addSession("r1", hostSess1, hostUser, clientA)
	tc.addSession("r1", hostSess2, hostUser, clientB)

	// hostUser is CLIENT for 1 session (should NOT be closed)
	clientSess := xid.New()
	tc.addSession("r1", clientSess, upstream, hostUser)

	room := tc.rooms.Rooms["r1"]
	closed := room.closeHostSessions(tc.rooms, hostUser)

	if len(closed) != 2 {
		t.Fatalf("expected 2 closed sessions, got %d", len(closed))
	}
	// Client-role session should survive
	if _, exists := room.Sessions[clientSess]; !exists {
		t.Fatal("client-role session should survive closeHostSessions")
	}
	if len(room.Sessions) != 1 {
		t.Fatalf("expected 1 surviving session, got %d", len(room.Sessions))
	}

	// Both clients should receive EndShare
	if !hasEndShareForSession(tc.collectMessages(clientA), hostSess1) {
		t.Error("clientA should receive EndShare for hostSess1")
	}
	if !hasEndShareForSession(tc.collectMessages(clientB), hostSess2) {
		t.Error("clientB should receive EndShare for hostSess2")
	}

	// upstream (host of the surviving session) should NOT receive EndShare
	if countEndShare(tc.collectMessages(upstream)) != 0 {
		t.Error("upstream should NOT receive EndShare")
	}

	// 2 closed sessions × 2 = 4 TURN Disallow calls
	if len(tc.turn.disallowed) != 4 {
		t.Errorf("expected 4 TURN Disallow calls, got %d: %v", len(tc.turn.disallowed), tc.turn.disallowed)
	}
}

// ---------------------------------------------------------------------------
// Room.closeAllSessions tests
// ---------------------------------------------------------------------------

func TestCloseAllSessions(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionTURN)

	u1 := xid.New()
	u2 := xid.New()
	u3 := xid.New()
	tc.addUser("r1", u1, true, true)
	tc.addUser("r1", u2, false, false)
	tc.addUser("r1", u3, false, false)

	sess1 := xid.New()
	sess2 := xid.New()
	sess3 := xid.New()
	tc.addSession("r1", sess1, u1, u2)
	tc.addSession("r1", sess2, u1, u3)
	tc.addSession("r1", sess3, u2, u3)

	room := tc.rooms.Rooms["r1"]
	room.closeAllSessions(tc.rooms)

	if len(room.Sessions) != 0 {
		t.Fatalf("expected 0 sessions after closeAllSessions, got %d", len(room.Sessions))
	}
	// 3 sessions × 2 = 6 TURN credential revocations
	if len(tc.turn.disallowed) != 6 {
		t.Errorf("expected 6 TURN Disallow calls, got %d", len(tc.turn.disallowed))
	}

	// closeAllSessions must NOT send any EndShare messages
	for _, uid := range []xid.ID{u1, u2, u3} {
		if n := countEndShare(tc.collectMessages(uid)); n != 0 {
			t.Errorf("user %s should not receive EndShare from closeAllSessions, got %d", uid, n)
		}
	}
}

// ---------------------------------------------------------------------------
// Rooms.removeUserFromRoom — full orchestration tests
// ---------------------------------------------------------------------------

func TestRemoveUserFromRoom_NormalMemberLeaves(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionTURN)

	ownerID := xid.New()
	memberID := xid.New()
	otherID := xid.New()
	tc.addUser("r1", ownerID, true, true)
	tc.addUser("r1", memberID, false, false)
	tc.addUser("r1", otherID, false, false)

	// member is involved in 2 sessions
	sess1 := xid.New() // owner(sharing) → member(viewing)
	sess2 := xid.New() // member(sharing) → other(viewing)
	tc.addSession("r1", sess1, ownerID, memberID)
	tc.addSession("r1", sess2, memberID, otherID)

	tc.rooms.removeUserFromRoom("r1", memberID)

	room := tc.rooms.Rooms["r1"]

	// Room should survive
	if room == nil {
		t.Fatal("room should still exist")
	}
	// member should be removed
	if _, exists := room.Users[memberID]; exists {
		t.Fatal("member should be removed from Users map")
	}
	if len(room.Users) != 2 {
		t.Fatalf("expected 2 remaining users, got %d", len(room.Users))
	}
	// Both sessions involving member should be closed
	if len(room.Sessions) != 0 {
		t.Fatalf("expected 0 remaining sessions, got %d", len(room.Sessions))
	}

	// owner (host of sess1) should receive EndShare
	ownerMsgs := tc.collectMessages(ownerID)
	if !hasEndShareForSession(ownerMsgs, sess1) {
		t.Error("owner should receive EndShare for sess1")
	}
	// other (client of sess2) should receive EndShare
	otherMsgs := tc.collectMessages(otherID)
	if !hasEndShareForSession(otherMsgs, sess2) {
		t.Error("other should receive EndShare for sess2")
	}

	// Remaining users should receive room info broadcast
	if countRoomMsg(ownerMsgs) != 1 {
		t.Errorf("expected 1 Room message for owner, got %d", countRoomMsg(ownerMsgs))
	}
	if countRoomMsg(otherMsgs) != 1 {
		t.Errorf("expected 1 Room message for other, got %d", countRoomMsg(otherMsgs))
	}

	// TURN: 2 sessions × 2 = 4 Disallow calls
	if len(tc.turn.disallowed) != 4 {
		t.Errorf("expected 4 TURN Disallow calls, got %d", len(tc.turn.disallowed))
	}
}

func TestRemoveUserFromRoom_OwnerLeaves_KeepRoom(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionSTUN) // CloseOnOwnerLeave = false

	ownerID := xid.New()
	memberID := xid.New()
	tc.addUser("r1", ownerID, true, false)
	tc.addUser("r1", memberID, false, false)

	tc.rooms.removeUserFromRoom("r1", ownerID)

	room := tc.rooms.Rooms["r1"]
	if room == nil {
		t.Fatal("room should survive when CloseOnOwnerLeave=false")
	}
	if _, exists := room.Users[ownerID]; exists {
		t.Fatal("owner should be removed")
	}
	if len(room.Users) != 1 {
		t.Fatalf("expected 1 remaining user, got %d", len(room.Users))
	}
	// member should NOT be force-disconnected
	if _, connected := tc.rooms.connected[memberID]; !connected {
		t.Fatal("member should remain in connected map")
	}
	// member should receive room info notification
	memberMsgs := tc.collectMessages(memberID)
	if countRoomMsg(memberMsgs) != 1 {
		t.Errorf("expected 1 Room message for member, got %d", countRoomMsg(memberMsgs))
	}
	// member should NOT receive CloseWriter
	if countCloseWriter(memberMsgs) != 0 {
		t.Error("member should not receive CloseWriter")
	}
}

func TestRemoveUserFromRoom_OwnerLeaves_CloseRoom(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", true, ConnectionSTUN) // CloseOnOwnerLeave = true

	ownerID := xid.New()
	memberB := xid.New()
	memberC := xid.New()
	tc.addUser("r1", ownerID, true, true)
	tc.addUser("r1", memberB, false, false)
	tc.addUser("r1", memberC, false, false)

	// session that doesn't involve the owner
	sessBC := xid.New()
	tc.addSession("r1", sessBC, memberB, memberC)

	tc.rooms.removeUserFromRoom("r1", ownerID)

	// Room should be destroyed
	if _, exists := tc.rooms.Rooms["r1"]; exists {
		t.Fatal("room should be destroyed")
	}
	// Remaining users should be force-disconnected
	if _, connected := tc.rooms.connected[memberB]; connected {
		t.Fatal("memberB should be removed from connected map")
	}
	if _, connected := tc.rooms.connected[memberC]; connected {
		t.Fatal("memberC should be removed from connected map")
	}

	// Both remaining users should receive CloseWriter
	bMsgs := tc.collectMessages(memberB)
	cMsgs := tc.collectMessages(memberC)
	if countCloseWriter(bMsgs) != 1 {
		t.Errorf("memberB expected 1 CloseWriter, got %d", countCloseWriter(bMsgs))
	}
	if countCloseWriter(cMsgs) != 1 {
		t.Errorf("memberC expected 1 CloseWriter, got %d", countCloseWriter(cMsgs))
	}
}

func TestRemoveUserFromRoom_LastUserLeaves(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionTURN)

	userID := xid.New()
	tc.addUser("r1", userID, true, false)

	// Create a session where the user is both host and client (edge case)
	sessID := xid.New()
	tc.addSession("r1", sessID, userID, userID)

	tc.rooms.removeUserFromRoom("r1", userID)

	if _, exists := tc.rooms.Rooms["r1"]; exists {
		t.Fatal("room should be destroyed when last user leaves")
	}
	// closeUserSessions runs before removeUser in the orchestrator,
	// so the user is still in the Users map when EndShare is sent.
	// For sessID: Host==userID → sends EndShare to Client (which is also userID).
	// closeSession revokes both host+client TURN creds.
	if len(tc.turn.disallowed) < 2 {
		t.Errorf("expected at least 2 TURN Disallow calls, got %d: %v",
			len(tc.turn.disallowed), tc.turn.disallowed)
	}
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

func TestRemoveUserFromRoom_UserNotInRoom(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionSTUN)

	// Call with a userID that doesn't exist in the room
	tc.rooms.removeUserFromRoom("r1", xid.New())

	// Room should still exist unchanged
	room := tc.rooms.Rooms["r1"]
	if room == nil {
		t.Fatal("room should still exist")
	}
	if len(room.Users) != 0 {
		t.Fatalf("room should have no users, got %d", len(room.Users))
	}
}

func TestRemoveUserFromRoom_RoomDoesNotExist(t *testing.T) {
	tc := newTestContext()

	// Should not panic
	tc.rooms.removeUserFromRoom("nonexistent", xid.New())
}

func TestRemoveUserFromRoom_DoubleDisconnect(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionSTUN)

	ownerID := xid.New()
	leavingID := xid.New()
	tc.addUser("r1", ownerID, true, false)
	tc.addUser("r1", leavingID, false, false)

	// First disconnect — should succeed
	tc.rooms.removeUserFromRoom("r1", leavingID)

	if _, exists := tc.rooms.Rooms["r1"].Users[leavingID]; exists {
		t.Fatal("user should be removed after first disconnect")
	}

	// Second disconnect — should be a no-op
	tc.rooms.removeUserFromRoom("r1", leavingID)

	// Room should still exist with just the owner
	room := tc.rooms.Rooms["r1"]
	if room == nil {
		t.Fatal("room should still exist")
	}
	if len(room.Users) != 1 {
		t.Fatalf("expected 1 remaining user, got %d", len(room.Users))
	}
}

// ---------------------------------------------------------------------------
// Rooms.closeRoom tests
// ---------------------------------------------------------------------------

func TestCloseRoom_DisconnectsRemainingUsers(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionTURN)

	u1 := xid.New()
	u2 := xid.New()
	u3 := xid.New()
	tc.addUser("r1", u1, true, true)
	tc.addUser("r1", u2, false, false)
	tc.addUser("r1", u3, false, false)

	sess1 := xid.New()
	sess2 := xid.New()
	tc.addSession("r1", sess1, u1, u2)
	tc.addSession("r1", sess2, u2, u3)

	tc.rooms.closeRoom("r1")

	// Room should be destroyed
	if _, exists := tc.rooms.Rooms["r1"]; exists {
		t.Fatal("room should be destroyed")
	}

	// All 3 users should be disconnected from the connected map
	for _, uid := range []xid.ID{u1, u2, u3} {
		if _, connected := tc.rooms.connected[uid]; connected {
			t.Errorf("user %s should be removed from connected map", uid)
		}
	}

	// All 3 users should receive CloseWriter
	for _, uid := range []xid.ID{u1, u2, u3} {
		msgs := tc.collectMessages(uid)
		if countCloseWriter(msgs) != 1 {
			t.Errorf("user %s expected 1 CloseWriter, got %d", uid, countCloseWriter(msgs))
		}
	}

	// TURN: 2 sessions × 2 = 4 Disallow calls
	if len(tc.turn.disallowed) != 4 {
		t.Errorf("expected 4 TURN Disallow calls, got %d: %v", len(tc.turn.disallowed), tc.turn.disallowed)
	}
}

func TestCloseRoom_IdempotentOnMissingRoom(t *testing.T) {
	tc := newTestContext()
	// Should not panic on non-existent room
	tc.rooms.closeRoom("nonexistent")
}

// ---------------------------------------------------------------------------
// Integration tests — full event handlers
// ---------------------------------------------------------------------------

func TestDisconnected_Execute_Integration(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", true, ConnectionSTUN) // CloseOnOwnerLeave = true

	ownerID := xid.New()
	memberID := xid.New()
	tc.addUser("r1", ownerID, true, true)
	tc.addUser("r1", memberID, false, false)

	sessID := xid.New()
	tc.addSession("r1", sessID, ownerID, memberID)

	// Simulate owner disconnect via the full Disconnected event path
	dis := &Disconnected{Code: 1000, Reason: "normal closure"}
	dis.executeNoError(tc.rooms, ClientInfo{
		ID:    ownerID,
		Write: tc.writes[ownerID],
	})

	// Owner should be removed from connected map
	if _, connected := tc.rooms.connected[ownerID]; connected {
		t.Fatal("owner should be removed from connected map")
	}
	// Owner should receive CloseWriter from executeNoError
	ownerMsgs := tc.collectMessages(ownerID)
	if countCloseWriter(ownerMsgs) != 1 {
		t.Errorf("owner expected 1 CloseWriter, got %d", countCloseWriter(ownerMsgs))
	}

	// Room should be destroyed (owner left + CloseOnOwnerLeave)
	if _, exists := tc.rooms.Rooms["r1"]; exists {
		t.Fatal("room should be destroyed")
	}
	// member should be force-disconnected by closeRoom
	if _, connected := tc.rooms.connected[memberID]; connected {
		t.Fatal("member should be removed from connected map")
	}
	memberMsgs := tc.collectMessages(memberID)
	if countCloseWriter(memberMsgs) != 1 {
		t.Errorf("member expected 1 CloseWriter, got %d", countCloseWriter(memberMsgs))
	}
}

func TestStopShare_Execute_Integration(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionSTUN)

	hostID := xid.New()
	clientID := xid.New()
	tc.addUser("r1", hostID, true, true) // owner, streaming
	tc.addUser("r1", clientID, false, false)

	sessID := xid.New()
	tc.addSession("r1", sessID, hostID, clientID)

	// Execute StopShare via the full event handler
	e := &StopShare{}
	err := e.Execute(tc.rooms, ClientInfo{ID: hostID})
	if err != nil {
		t.Fatalf("StopShare.Execute() returned error: %v", err)
	}

	// host should no longer be streaming
	room := tc.rooms.Rooms["r1"]
	if room.Users[hostID].Streaming {
		t.Fatal("host should have Streaming=false after StopShare")
	}

	// Session should be closed
	if _, exists := room.Sessions[sessID]; exists {
		t.Fatal("session should be closed")
	}

	// client should receive EndShare
	clientMsgs := tc.collectMessages(clientID)
	if !hasEndShareForSession(clientMsgs, sessID) {
		t.Error("client should receive EndShare")
	}

	// Both users should receive room info notification
	hostMsgs := tc.collectMessages(hostID)
	if countRoomMsg(hostMsgs) != 1 {
		t.Errorf("host expected 1 Room message, got %d", countRoomMsg(hostMsgs))
	}
	if countRoomMsg(clientMsgs) != 1 {
		t.Errorf("client expected 1 Room message, got %d", countRoomMsg(clientMsgs))
	}
}

// ---------------------------------------------------------------------------
// notifyInfoChanged sort-order verification
// ---------------------------------------------------------------------------

func TestNotifyInfoChanged_SortOrder(t *testing.T) {
	tc := newTestContext()
	tc.addRoom("r1", false, ConnectionSTUN)

	ownerID := xid.New()
	aliceID := xid.New()
	bobID := xid.New()
	tc.addUser("r1", ownerID, true, false)
	tc.addUser("r1", aliceID, false, true) // streaming
	tc.addUser("r1", bobID, false, false)

	// Override names for deterministic sort
	tc.rooms.Rooms["r1"].Users[aliceID].Name = "Alice"
	tc.rooms.Rooms["r1"].Users[bobID].Name = "Bob"
	tc.rooms.Rooms["r1"].Users[ownerID].Name = "Zara"

	room := tc.rooms.Rooms["r1"]
	room.notifyInfoChanged()

	// Expected sort: owner first, then streaming, then alphabetical
	// Zara (owner) → Alice (streaming) → Bob (non-streaming, alphabetical)
	aliceMsgs := tc.collectMessages(aliceID)
	if !hasUserSorted(aliceMsgs, []xid.ID{ownerID, aliceID, bobID}) {
		t.Error("users should be sorted: owner first, then streaming, then alphabetical")
	}
}
