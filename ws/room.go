package ws

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"github.com/screego/server/config"
	"github.com/screego/server/ws/outgoing"
)

type ConnectionMode string

const (
	ConnectionLocal ConnectionMode = "local"
	ConnectionSTUN  ConnectionMode = "stun"
	ConnectionTURN  ConnectionMode = config.AuthModeTurn
)

type Room struct {
	ID                string
	CloseOnOwnerLeave bool
	Mode              ConnectionMode
	Users             map[xid.ID]*User
	Sessions          map[xid.ID]*RoomSession
}

const (
	CloseOwnerLeft = "Owner Left"
	CloseDone      = "Read End"
)

func (r *Room) newSession(host, client xid.ID, rooms *Rooms, v4, v6 net.IP) {
	id := xid.New()
	r.Sessions[id] = &RoomSession{
		Host:   host,
		Client: client,
	}
	sessionCreatedTotal.Inc()

	iceHost := []outgoing.ICEServer{}
	iceClient := []outgoing.ICEServer{}
	switch r.Mode {
	case ConnectionLocal:
	case ConnectionSTUN:
		iceHost = []outgoing.ICEServer{{URLs: rooms.addresses("stun", v4, v6, false)}}
		iceClient = []outgoing.ICEServer{{URLs: rooms.addresses("stun", v4, v6, false)}}
	case ConnectionTURN:
		hostName, hostPW := rooms.turnServer.Credentials(id.String()+"host", r.Users[host].Addr)
		clientName, clientPW := rooms.turnServer.Credentials(id.String()+"client", r.Users[client].Addr)
		iceHost = []outgoing.ICEServer{{
			URLs:       rooms.addresses("turn", v4, v6, true),
			Credential: hostPW,
			Username:   hostName,
		}}
		iceClient = []outgoing.ICEServer{{
			URLs:       rooms.addresses("turn", v4, v6, true),
			Credential: clientPW,
			Username:   clientName,
		}}
	}
	r.Users[host].WriteTimeout(outgoing.HostSession{Peer: client, ID: id, ICEServers: iceHost})
	r.Users[client].WriteTimeout(outgoing.ClientSession{Peer: host, ID: id, ICEServers: iceClient})
}

func (r *Rooms) addresses(prefix string, v4, v6 net.IP, tcp bool) (result []string) {
	if v4 != nil {
		result = append(result, fmt.Sprintf("%s:%s:%s", prefix, v4.String(), r.config.TurnPort))
		if tcp {
			result = append(result, fmt.Sprintf("%s:%s:%s?transport=tcp", prefix, v4.String(), r.config.TurnPort))
		}
	}
	if v6 != nil {
		result = append(result, fmt.Sprintf("%s:[%s]:%s", prefix, v6.String(), r.config.TurnPort))
		if tcp {
			result = append(result, fmt.Sprintf("%s:[%s]:%s?transport=tcp", prefix, v6.String(), r.config.TurnPort))
		}
	}
	return
}

func (r *Room) closeSession(rooms *Rooms, id xid.ID) {
	if r.Mode == ConnectionTURN {
		rooms.turnServer.Disallow(id.String() + "host")
		rooms.turnServer.Disallow(id.String() + "client")
	}
	delete(r.Sessions, id)
	sessionClosedTotal.Inc()
}

// removeUser deletes a user from the room's Users map and increments
// usersLeftTotal. Returns true if the user was present and removed.
// This is a pure data mutation — it does NOT close sessions or trigger
// room destruction. Callers orchestrate those concerns separately.
func (r *Room) removeUser(userID xid.ID) bool {
	if _, ok := r.Users[userID]; !ok {
		return false
	}
	delete(r.Users, userID)
	usersLeftTotal.Inc()
	return true
}

// electOwner promotes a remaining user to room owner when the previous
// owner has left but the room continues to exist (CloseOnOwnerLeave=false).
// Without this, notifyInfoChanged would broadcast a member list in which no
// one is Owner, leaving the room permanently anchorless for owner-based
// management, default display, and future control features.
//
// The most senior remaining user is chosen: xid.IDs embed a big-endian
// timestamp, so the smallest ID corresponds to the earliest-joined member.
// This makes the choice deterministic and stable across calls.
//
// It is a no-op returning nil if the room already has an owner (so it is
// safe to call when no transfer is needed) or if no users remain. On
// success it marks the chosen user Owner and returns them.
func (r *Room) electOwner() *User {
	var next *User
	for _, user := range r.Users {
		if user.Owner {
			// An owner is already present; no transfer needed.
			return nil
		}
		if next == nil || user.ID.Compare(next.ID) < 0 {
			next = user
		}
	}
	if next == nil {
		return nil
	}
	next.Owner = true
	return next
}

// closeUserSessions closes every session where userID participates as
// host OR client. For each closed session, an EndShare notification is
// sent to the surviving peer (if still present in the room), TURN
// credentials are revoked, and the session is removed from the map.
// Returns the IDs of all sessions that were actually closed.
func (r *Room) closeUserSessions(rooms *Rooms, userID xid.ID) []xid.ID {
	var closed []xid.ID
	for id, session := range r.Sessions {
		if session.Host == userID {
			if client, ok := r.Users[session.Client]; ok {
				client.WriteTimeout(outgoing.EndShare(id))
			}
			r.closeSession(rooms, id)
			closed = append(closed, id)
		} else if session.Client == userID {
			if host, ok := r.Users[session.Host]; ok {
				host.WriteTimeout(outgoing.EndShare(id))
			}
			r.closeSession(rooms, id)
			closed = append(closed, id)
		}
	}
	return closed
}

// closeHostSessions closes only sessions where userID is the Host
// (screen sharer). For each closed session, an EndShare notification
// is sent to the Client (viewer). Used by the StopShare event.
// Returns the IDs of all sessions that were closed.
func (r *Room) closeHostSessions(rooms *Rooms, userID xid.ID) []xid.ID {
	var closed []xid.ID
	for id, session := range r.Sessions {
		if session.Host == userID {
			if client, ok := r.Users[session.Client]; ok {
				client.WriteTimeout(outgoing.EndShare(id))
			}
			r.closeSession(rooms, id)
			closed = append(closed, id)
		}
	}
	return closed
}

// closeAllSessions closes every remaining session in the room,
// revoking TURN credentials for each. Does NOT send EndShare
// notifications — intended for room destruction scenarios where
// peers are already being disconnected.
func (r *Room) closeAllSessions(rooms *Rooms) {
	for id := range r.Sessions {
		r.closeSession(rooms, id)
	}
}

type RoomSession struct {
	Host   xid.ID
	Client xid.ID
}

func (r *Room) notifyInfoChanged() {
	for _, current := range r.Users {
		users := []outgoing.User{}
		for _, user := range r.Users {
			users = append(users, outgoing.User{
				ID:        user.ID,
				Name:      user.Name,
				Streaming: user.Streaming,
				You:       current == user,
				Owner:     user.Owner,
			})
		}

		sort.Slice(users, func(i, j int) bool {
			left := users[i]
			right := users[j]

			if left.Owner != right.Owner {
				return left.Owner
			}

			if left.Streaming != right.Streaming {
				return left.Streaming
			}

			return left.Name < right.Name
		})

		current.WriteTimeout(outgoing.Room{
			ID:    r.ID,
			Users: users,
		})
	}
}

type User struct {
	ID        xid.ID
	Addr      net.IP
	Name      string
	Streaming bool
	Owner     bool
	_write    chan<- outgoing.Message
}

func (u *User) WriteTimeout(msg outgoing.Message) {
	writeTimeout(u._write, msg)
}

func writeTimeout[T any](ch chan<- T, msg T) {
	select {
	case <-time.After(2 * time.Second):
		log.Warn().Interface("event", fmt.Sprintf("%T", msg)).Interface("payload", msg).Msg("Client write loop didn't accept the message.")
	case ch <- msg:
	}
}
