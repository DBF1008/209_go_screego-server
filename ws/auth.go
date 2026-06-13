package ws

import (
	"errors"

	"github.com/screego/server/config"
)

// checkAuth enforces the configured authentication mode for room creation and
// joining. The mode parameter is the connection mode of the room being created
// or the existing room being joined.
func checkAuth(rooms *Rooms, mode ConnectionMode, authenticated bool) error {
	switch rooms.config.AuthMode {
	case config.AuthModeNone:
		return nil
	case config.AuthModeAll:
		if !authenticated {
			return errors.New("you need to login")
		}
	case config.AuthModeTurn:
		if mode != ConnectionSTUN && mode != ConnectionLocal && !authenticated {
			return errors.New("you need to login")
		}
	default:
		return errors.New("invalid authmode:" + rooms.config.AuthMode)
	}
	return nil
}
