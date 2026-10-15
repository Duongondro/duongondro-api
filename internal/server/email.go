package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/service"
)

func (s *Server) RequestEmailConfirmation(ctx context.Context, req api.RequestEmailConfirmationRequestObject) (api.RequestEmailConfirmationResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.RequestEmailConfirmation401Response{}, nil
	}
	err = s.signIn.RequestEmailConfirmation(ctx, user.ID, req.Body.Email, service.ConfirmLinkBase(s.magicLinkBase))
	if errors.Is(err, service.ErrMailRateLimited) || errors.Is(err, service.ErrEmailConfirmationRateLimited) ||
		errors.Is(err, service.ErrEmailConfirmationNetworkLimited) {
		return api.RequestEmailConfirmation429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		if kind, body, ok := clientError(err); ok && kind == http.StatusBadRequest {
			return api.RequestEmailConfirmation400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.RequestEmailConfirmation204Response{}, nil
}

func (s *Server) ConfirmEmail(ctx context.Context, req api.ConfirmEmailRequestObject) (api.ConfirmEmailResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ConfirmEmail401Response{}, nil
	}
	switch b := req.Body; {
	case b.Code != nil && b.Token == nil:
		err = s.signIn.ConfirmEmailCode(ctx, user.ID, *b.Code)
	case b.Code == nil && b.Token != nil:
		err = s.signIn.ConfirmEmailLink(ctx, user.ID, *b.Token)
	default:
		return api.ConfirmEmail400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(errorBody(
			errors.New("send the code from the mail, or the link's token")))}, nil
	}
	if err == nil {
		return api.ConfirmEmail204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.ConfirmEmail400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.ConfirmEmail409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	case ok && kind == http.StatusNotFound:
		// The account was deleted meanwhile; its session is gone with it.
		return api.ConfirmEmail401Response{}, nil
	}
	return nil, err
}

func (s *Server) RemoveEmail(ctx context.Context, req api.RemoveEmailRequestObject) (api.RemoveEmailResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.RemoveEmail401Response{}, nil
	}
	err = s.signIn.RemoveEmail(ctx, user.ID)
	if err == nil {
		return api.RemoveEmail204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusConflict:
		return api.RemoveEmail409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	case ok && kind == http.StatusNotFound:
		return api.RemoveEmail401Response{}, nil
	}
	return nil, err
}
