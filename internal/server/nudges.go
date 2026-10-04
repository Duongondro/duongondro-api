package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/service"
)

func (s *Server) PutPushToken(ctx context.Context, req api.PutPushTokenRequestObject) (api.PutPushTokenResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutPushToken401Response{}, nil
	}
	err = s.nudges.PutToken(ctx, user.ID, req.DeviceId, string(req.Body.Platform), req.Body.Token)
	if err == nil {
		return api.PutPushToken204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.PutPushToken400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusNotFound:
		return api.PutPushToken404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) DeletePushToken(ctx context.Context, req api.DeletePushTokenRequestObject) (api.DeletePushTokenResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.DeletePushToken401Response{}, nil
	}
	err = s.nudges.DeleteToken(ctx, user.ID, req.DeviceId)
	if errors.Is(err, service.ErrNotFound) {
		return api.DeletePushToken404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.DeletePushToken204Response{}, nil
}

func (s *Server) PutFriendSettings(ctx context.Context, req api.PutFriendSettingsRequestObject) (api.PutFriendSettingsResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutFriendSettings401Response{}, nil
	}
	err = s.nudges.SetNotifyDone(ctx, user.ID, req.UserId, req.Body.NotifyDone)
	if errors.Is(err, service.ErrNotFound) {
		return api.PutFriendSettings404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.PutFriendSettings204Response{}, nil
}

func (s *Server) Poke(ctx context.Context, req api.PokeRequestObject) (api.PokeResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.Poke401Response{}, nil
	}
	err = s.nudges.Poke(ctx, user, req.UserId)
	switch {
	case err == nil:
		return api.Poke204Response{}, nil
	case errors.Is(err, service.ErrAlreadyPoked):
		return api.Poke409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(errorBody(err))}, nil
	case errors.Is(err, service.ErrNotFound):
		return api.Poke404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	}
	return nil, err
}
