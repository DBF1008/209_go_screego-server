package ws

import (
	"github.com/screego/server/ws/outgoing"
)

type Disconnected struct {
	Code   int
	Reason string
}

func (e *Disconnected) Execute(rooms *Rooms, current ClientInfo) error {
	e.executeNoError(rooms, current)
	return nil
}

func (e *Disconnected) executeNoError(rooms *Rooms, current ClientInfo) {
	roomID := rooms.connected[current.ID]
	delete(rooms.connected, current.ID)
	writeTimeout[outgoing.Message](current.Write, outgoing.CloseWriter{Code: e.Code, Reason: e.Reason})

	if roomID == "" {
		return
	}

	rooms.removeUserFromRoom(roomID, current.ID)
}
