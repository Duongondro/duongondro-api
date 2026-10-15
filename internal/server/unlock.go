package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/atrest"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// Passkeys that unlock the counts (docs/crypto.md › Passkey unlock).

func userKeyState(uk atrest.UserKey, wraps []db.UserKeyWrap) api.UserKeyState {
	out := api.UserKeyState{Id: uk.ID, Version: uk.Version,
		Statement: api.SignedStatement{Payload: uk.Payload, Signature: uk.Signature}, Wraps: make([]api.UserKeyWrap, len(wraps))}
	for i, w := range wraps {
		out.Wraps[i] = api.UserKeyWrap{UserKeyId: w.UserKeyID, Kind: int(w.Kind), KeyVersion: int(w.KeyVersion),
			EphemeralKey: w.EphemeralKey, Box: w.Box, Signature: w.Signature, CreatedAt: w.CreatedAt}
	}
	return out
}

func userKeyWrapInput(w api.UserKeyWrapInput) service.UserKeyWrapInput {
	return service.UserKeyWrapInput{UserKeyID: w.UserKeyId, Kind: w.Kind, KeyVersion: w.KeyVersion,
		EphemeralKey: w.EphemeralKey, Box: w.Box, Signature: w.Signature}
}

func (s *Server) GetUserKey(ctx context.Context, req api.GetUserKeyRequestObject) (api.GetUserKeyResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.GetUserKey401Response{}, nil
	}
	uk, wraps, err := s.unlock.UserKey(ctx, user.ID)
	if errors.Is(err, service.ErrNotFound) {
		return api.GetUserKey404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errors.New("no user key published yet")))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.GetUserKey200JSONResponse(userKeyState(uk, wraps)), nil
}

func (s *Server) PutUserKey(ctx context.Context, req api.PutUserKeyRequestObject) (api.PutUserKeyResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutUserKey401Response{}, nil
	}
	if err := s.unlock.PutUserKey(ctx, user, req.Body.Payload, req.Body.Signature); err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.PutUserKey400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusConflict:
			return api.PutUserKey409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.PutUserKey204Response{}, nil
}

func (s *Server) PutUserKeyWrap(ctx context.Context, req api.PutUserKeyWrapRequestObject) (api.PutUserKeyWrapResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutUserKeyWrap401Response{}, nil
	}
	if err := s.unlock.PutUserKeyWrap(ctx, user, userKeyWrapInput(*req.Body)); err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.PutUserKeyWrap400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusConflict:
			return api.PutUserKeyWrap409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.PutUserKeyWrap204Response{}, nil
}

func (s *Server) GetPasskeyUnlock(ctx context.Context, req api.GetPasskeyUnlockRequestObject) (api.GetPasskeyUnlockResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.GetPasskeyUnlock401Response{}, nil
	}
	notFound := api.GetPasskeyUnlock404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(service.ErrNotFound))}
	id, ok := credentialID(req.CredentialId)
	if !ok {
		return notFound, nil
	}
	u, err := s.unlock.PasskeyBox(ctx, user.ID, id)
	if errors.Is(err, service.ErrNotFound) {
		return notFound, nil
	} else if err != nil {
		return nil, err
	}
	return api.GetPasskeyUnlock200JSONResponse{Box: u.Box, Signature: u.Signature, UserKey: userKeyState(u.UserKey, u.Wraps)}, nil
}

func (s *Server) PutPasskeyUnlock(ctx context.Context, req api.PutPasskeyUnlockRequestObject) (api.PutPasskeyUnlockResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutPasskeyUnlock401Response{}, nil
	}
	id, ok := credentialID(req.CredentialId)
	if !ok {
		return api.PutPasskeyUnlock404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(service.ErrNotFound))}, nil
	}
	if err := s.unlock.PutPasskeyBox(ctx, user, id, req.Body.UserKeyId, req.Body.Box, req.Body.Signature); err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.PutPasskeyUnlock400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.PutPasskeyUnlock404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
		case ok && kind == http.StatusConflict:
			return api.PutPasskeyUnlock409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.PutPasskeyUnlock204Response{}, nil
}

func (s *Server) DeletePasskeyUnlock(ctx context.Context, req api.DeletePasskeyUnlockRequestObject) (api.DeletePasskeyUnlockResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.DeletePasskeyUnlock401Response{}, nil
	}
	notFound := api.DeletePasskeyUnlock404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(service.ErrNotFound))}
	id, ok := credentialID(req.CredentialId)
	if !ok {
		return notFound, nil
	}
	if err := s.unlock.DeletePasskeyBox(ctx, user.ID, id); errors.Is(err, service.ErrNotFound) {
		return notFound, nil
	} else if err != nil {
		return nil, err
	}
	return api.DeletePasskeyUnlock204Response{}, nil
}
