//go:build DEV

package auth

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/jackc/pgx/v5"
)

// ErrNoSuchUser answers a DEV sign-in as an id that does not exist.
var ErrNoSuchUser = errors.New("no such user")

// DevSession signs in without any sign-in method: as the user with the given id, or
// as a new user when id is empty. It exists so the Simulator and the emulator can
// use a local server before passkeys and Sign in with Apple are set up.
//
// Development builds only: this file is compiled only with the DEV build tag, so a
// plain build has no such method, and internal/server has no route that calls it.
func (s *Service) DevSession(ctx context.Context, id string) (token string, userID uuid.UUID, err error) {
	if id == "" {
		user, err := s.q.CreateUser(ctx)
		if err != nil {
			return "", uuid.UUID{}, fmt.Errorf("create user: %w", err)
		}
		userID = user.ID
	} else {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return "", uuid.UUID{}, ErrNoSuchUser
		}
		user, err := s.q.GetUser(ctx, parsed)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", uuid.UUID{}, ErrNoSuchUser
		} else if err != nil {
			return "", uuid.UUID{}, err
		}
		userID = user.ID
	}
	token, err = s.NewSession(ctx, userID)
	return token, userID, err
}
