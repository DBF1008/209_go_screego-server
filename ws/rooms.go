package ws

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"github.com/screego/server/auth"
	"github.com/screego/server/config"
	"github.com/screego/server/turn"
	"github.com/screego/server/util"
	"github.com/screego/server/ws/outgoing"
)

func NewRooms(tServer turn.Server, users *auth.Users, conf config.Config) *Rooms {
	return &Rooms{
		Rooms:      map[string]*Room{},
		Incoming:   make(chan ClientMessage),
		connected:  map[xid.ID]string{},
		turnServer: tServer,
		users:      users,
		config:     conf,
		r:          rand.New(rand.NewSource(time.Now().Unix())),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("origin")
				u, err := url.Parse(origin)
				if err != nil {
					return false
				}
				if u.Host == r.Host {
					return true
				}
				return conf.CheckOrigin(origin)
			},
		},
	}
}

type Rooms struct {
	turnServer turn.Server
	Rooms      map[string]*Room
	Incoming   chan ClientMessage
	upgrader   websocket.Upgrader
	users      *auth.Users
	config     config.Config
	r          *rand.Rand
	connected  map[xid.ID]string
}

func (r *Rooms) CurrentRoom(info ClientInfo) (*Room, error) {
	roomID, ok := r.connected[info.ID]
	if !ok {
		return nil, fmt.Errorf("not connected")
	}
	if roomID == "" {
		return nil, fmt.Errorf("not in a room")
	}
	room, ok := r.Rooms[roomID]
	if !ok {
		return nil, fmt.Errorf("room with id %s does not exist", roomID)
	}

	return room, nil
}

func (r *Rooms) RandUserName() string {
	return util.NewUserName(r.r)
}

func (r *Rooms) RandRoomName() string {
	return util.NewRoomName(r.r)
}

func (r *Rooms) Upgrade(w http.ResponseWriter, req *http.Request) {
	conn, err := r.upgrader.Upgrade(w, req, nil)
	if err != nil {
		log.Debug().Err(err).Msg("Websocket upgrade")
		w.WriteHeader(400)
		_, _ = fmt.Fprintf(w, "Upgrade failed %s", err)
		return
	}

	user, loggedIn := r.users.CurrentUser(req)
	c := newClient(conn, req, r.Incoming, user, loggedIn, r.config.TrustProxyHeaders)
	r.Incoming <- ClientMessage{Info: c.info, Incoming: Connected{}, SkipConnectedCheck: true}

	go c.startReading(time.Second * 20)
	go c.startWriteHandler(time.Second * 5)
}

func (r *Rooms) Start() {
	for msg := range r.Incoming {
		_, connected := r.connected[msg.Info.ID]
		if !msg.SkipConnectedCheck && !connected {
			log.Debug().Interface("event", fmt.Sprintf("%T", msg.Incoming)).Interface("payload", msg.Incoming).Msg("WebSocket Ignore")
			continue
		}

		if err := msg.Incoming.Execute(r, msg.Info); err != nil {
			dis := Disconnected{Code: websocket.CloseNormalClosure, Reason: err.Error()}
			dis.executeNoError(r, msg.Info)
		}
	}
}

func (r *Rooms) Count() (int, string) {
	timeout := time.After(5 * time.Second)

	h := Health{Response: make(chan int, 1)}
	select {
	case r.Incoming <- ClientMessage{SkipConnectedCheck: true, Incoming: &h}:
	case <-timeout:
		return -1, "main loop didn't accept a message within 5 second"
	}
	select {
	case count := <-h.Response:
		return count, ""
	case <-timeout:
		return -1, "main loop didn't respond to a message within 5 second"
	}
}

// removeUserFromRoom is the single authoritative entry point for "a user
// leaves a room." It orchestrates all four leave scenarios:
//
//  1. Normal member leaves → close their sessions, notify remaining users
//  2. Owner leaves + CloseOnOwnerLeave=false → same as normal member
//  3. Owner leaves + CloseOnOwnerLeave=true → force-disconnect all, destroy room
//  4. Last user leaves (room empty) → destroy room
//
// Connection-level concerns (removing from rooms.connected, sending the
// departing user's CloseWriter) are handled by the caller before invoking
// this method.
func (rs *Rooms) removeUserFromRoom(roomID string, userID xid.ID) {
	room, ok := rs.Rooms[roomID]
	if !ok {
		return
	}

	user, ok := room.Users[userID]
	if !ok {
		return
	}

	isOwner := user.Owner

	// Close every session involving this user, sending EndShare to
	// surviving peers and revoking TURN credentials.
	room.closeUserSessions(rs, userID)

	// Remove from Users map and bump the left-users metric.
	room.removeUser(userID)

	if isOwner && room.CloseOnOwnerLeave {
		// closeRoom force-disconnects all remaining users and tears down.
		rs.closeRoom(roomID)
		return
	}

	if len(room.Users) == 0 {
		rs.closeRoom(roomID)
		return
	}

	room.notifyInfoChanged()
}

// closeRoom tears down a room completely: force-disconnects any remaining
// users from their WebSocket connections (removing them from rs.connected
// and sending CloseWriter), closes all remaining sessions (revoking TURN
// credentials), deletes the room from rs.Rooms, and increments the
// roomsClosedTotal metric.
func (rs *Rooms) closeRoom(roomID string) {
	room, ok := rs.Rooms[roomID]
	if !ok {
		return
	}

	// Force-disconnect all remaining users.
	for _, member := range room.Users {
		delete(rs.connected, member.ID)
		member.WriteTimeout(outgoing.CloseWriter{
			Code:   websocket.CloseNormalClosure,
			Reason: CloseOwnerLeft,
		})
	}
	usersLeftTotal.Add(float64(len(room.Users)))

	// Close all remaining sessions (TURN credential revocation).
	room.closeAllSessions(rs)

	delete(rs.Rooms, roomID)
	roomsClosedTotal.Inc()
}
