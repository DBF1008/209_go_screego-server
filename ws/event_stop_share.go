package ws

func init() {
	register("stopshare", func() Event {
		return &StopShare{}
	})
}

type StopShare struct{}

func (e *StopShare) Execute(rooms *Rooms, current ClientInfo) error {
	room, err := rooms.CurrentRoom(current)
	if err != nil {
		return err
	}

	room.Users[current.ID].Streaming = false
	room.closeHostSessions(rooms, current.ID)
	room.notifyInfoChanged()
	return nil
}
