package ws

import (
	"fmt"

	"github.com/rs/xid"
)

func init() {
	register("create", func() Event {
		return &Create{}
	})
}

type Create struct {
	ID                string         `json:"id"`
	Mode              ConnectionMode `json:"mode"`
	CloseOnOwnerLeave bool           `json:"closeOnOwnerLeave"`
	UserName          string         `json:"username"`
	JoinIfExist       bool           `json:"joinIfExist,omitempty"`
}

func (e *Create) Execute(rooms *Rooms, current ClientInfo) error {
	if rooms.connected[current.ID] != "" {
		return fmt.Errorf("cannot join room, you are already in one")
	}

	if _, ok := rooms.Rooms[e.ID]; ok {
		if e.JoinIfExist {
			join := &Join{UserName: e.UserName, ID: e.ID}
			return join.Execute(rooms, current)
		}

		return fmt.Errorf("room with id %s does already exist", e.ID)
	}

	name := e.UserName
	if current.Authenticated {
		name = current.AuthenticatedUser
	}
	if name == "" {
		name = rooms.RandUserName()
	}

	if err := checkAuth(rooms, e.Mode, current.Authenticated); err != nil {
		return err
	}

	room := &Room{
		ID:                e.ID,
		CloseOnOwnerLeave: e.CloseOnOwnerLeave,
		Mode:              e.Mode,
		Sessions:          map[xid.ID]*RoomSession{},
		Users: map[xid.ID]*User{
			current.ID: {
				ID:        current.ID,
				Name:      name,
				Streaming: false,
				Owner:     true,
				Addr:      current.Addr,
				_write:    current.Write,
			},
		},
	}
	rooms.connected[current.ID] = room.ID
	rooms.Rooms[e.ID] = room
	room.notifyInfoChanged()
	usersJoinedTotal.Inc()
	roomsCreatedTotal.Inc()
	return nil
}
