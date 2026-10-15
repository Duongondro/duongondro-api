package server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// credentialID reads a passkey's id from the path: base64url without padding. One
// that does not decode names no passkey of the account, so it is a 404.
func credentialID(s api.CredentialId) ([]byte, bool) {
	id, err := base64.RawURLEncoding.DecodeString(s)
	return id, err == nil && len(id) > 0
}

func (s *Server) ListPasskeys(ctx context.Context, req api.ListPasskeysRequestObject) (api.ListPasskeysResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ListPasskeys401Response{}, nil
	}
	token, _ := auth.BearerPrefix(req.Params.Authorization)
	current, err := s.auth.SessionCredential(ctx, token)
	if errors.Is(err, auth.ErrInvalidToken) {
		return api.ListPasskeys401Response{}, nil
	} else if err != nil {
		return nil, err
	}
	keys, err := s.signIn.Passkeys(ctx, user.ID, current)
	if err != nil {
		return nil, err
	}
	out := api.ListPasskeys200JSONResponse{Passkeys: make([]api.Passkey, len(keys))}
	for i, k := range keys {
		p := api.Passkey{Id: base64.RawURLEncoding.EncodeToString(k.ID), Name: k.Name, CreatedAt: k.CreatedAt,
			LastUsedAt: k.LastUsedAt, Current: k.Current}
		if k.AAGUID != nil {
			a := k.AAGUID.String()
			p.Aaguid = &a
		}
		out.Passkeys[i] = p
	}
	return out, nil
}

func (s *Server) RenamePasskey(ctx context.Context, req api.RenamePasskeyRequestObject) (api.RenamePasskeyResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.RenamePasskey401Response{}, nil
	}
	id, ok := credentialID(req.CredentialId)
	if !ok {
		return api.RenamePasskey404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(service.ErrNotFound))}, nil
	}
	var name *string
	if v, err := req.Body.Name.Get(); err == nil {
		name = &v
	}
	if err := s.signIn.RenamePasskey(ctx, user.ID, id, name); err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.RenamePasskey400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.RenamePasskey404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.RenamePasskey204Response{}, nil
}

func (s *Server) DeletePasskey(ctx context.Context, req api.DeletePasskeyRequestObject) (api.DeletePasskeyResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.DeletePasskey401Response{}, nil
	}
	id, ok := credentialID(req.CredentialId)
	if !ok {
		return api.DeletePasskey404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(service.ErrNotFound))}, nil
	}
	if err := s.signIn.RemovePasskey(ctx, user.ID, id); err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusNotFound:
			return api.DeletePasskey404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
		case ok && kind == http.StatusConflict:
			return api.DeletePasskey409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.DeletePasskey204Response{}, nil
}
