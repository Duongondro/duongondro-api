package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/service"
)

func inviteProof(p *api.InviteProof) *service.InviteProof {
	if p == nil {
		return nil
	}
	return &service.InviteProof{ID: p.Id, Auth: p.Auth}
}

func ceremony(c service.Ceremony) (api.Ceremony, error) {
	raw, err := json.Marshal(c.Options)
	if err != nil {
		return api.Ceremony{}, err
	}
	var options map[string]any
	if err := json.Unmarshal(raw, &options); err != nil {
		return api.Ceremony{}, err
	}
	return api.Ceremony{SessionId: c.SessionID, Options: options}, nil
}

func signInResult(s service.Session) api.SignInResult {
	return api.SignInResult{Token: s.Token, UserId: s.UserID, Created: s.Created}
}

func credentialJSON(m map[string]any) json.RawMessage {
	raw, _ := json.Marshal(m)
	return raw
}

func (s *Server) BeginPasskeySignUp(ctx context.Context, req api.BeginPasskeySignUpRequestObject) (api.BeginPasskeySignUpResponseObject, error) {
	c, err := s.signIn.BeginPasskeySignUp(ctx, *inviteProof(&req.Body.Invite))
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.BeginPasskeySignUp400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.BeginPasskeySignUp404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errors.New("no such invitation")))}, nil
		}
		return nil, err
	}
	out, err := ceremony(c)
	return api.BeginPasskeySignUp200JSONResponse(out), err
}

func (s *Server) BeginPasskeySignIn(ctx context.Context, _ api.BeginPasskeySignInRequestObject) (api.BeginPasskeySignInResponseObject, error) {
	c, err := s.signIn.BeginPasskeySignIn(ctx)
	if err != nil {
		return nil, err
	}
	out, err := ceremony(c)
	return api.BeginPasskeySignIn200JSONResponse(out), err
}

func (s *Server) FinishPasskey(ctx context.Context, req api.FinishPasskeyRequestObject) (api.FinishPasskeyResponseObject, error) {
	session, err := s.signIn.FinishPasskey(ctx, req.SessionId, credentialJSON(req.Body.Credential))
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.FinishPasskey400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.FinishPasskey404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errors.New("the invitation is no longer valid")))}, nil
		}
		return nil, err
	}
	return api.FinishPasskey200JSONResponse(signInResult(session)), nil
}

func (s *Server) BeginPasskeyAdd(ctx context.Context, req api.BeginPasskeyAddRequestObject) (api.BeginPasskeyAddResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.BeginPasskeyAdd401Response{}, nil
	}
	c, err := s.signIn.BeginPasskeyAdd(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	out, err := ceremony(c)
	return api.BeginPasskeyAdd200JSONResponse(out), err
}

func (s *Server) FinishPasskeyAdd(ctx context.Context, req api.FinishPasskeyAddRequestObject) (api.FinishPasskeyAddResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.FinishPasskeyAdd401Response{}, nil
	}
	_, err = s.signIn.FinishPasskeyRegistration(ctx, req.SessionId, credentialJSON(req.Body.Credential), &user.ID)
	if err != nil {
		if kind, body, ok := clientError(err); ok && kind == http.StatusBadRequest {
			return api.FinishPasskeyAdd400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.FinishPasskeyAdd204Response{}, nil
}

func (s *Server) ProviderSignIn(ctx context.Context, req api.ProviderSignInRequestObject) (api.ProviderSignInResponseObject, error) {
	b := req.Body
	code := ""
	if b.AuthorizationCode != nil {
		code = *b.AuthorizationCode
	}
	session, err := s.signIn.ProviderSignIn(ctx, string(req.Provider), b.IdToken, b.Nonce, code, inviteProof(b.Invite))
	if errors.Is(err, service.ErrNoAccount) {
		return api.ProviderSignIn403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.ProviderSignIn400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.ProviderSignIn404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errors.New("no such invitation")))}, nil
		}
		return nil, err
	}
	return api.ProviderSignIn200JSONResponse(signInResult(session)), nil
}

func (s *Server) LinkProvider(ctx context.Context, req api.LinkProviderRequestObject) (api.LinkProviderResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.LinkProvider401Response{}, nil
	}
	b := req.Body
	code := ""
	if b.AuthorizationCode != nil {
		code = *b.AuthorizationCode
	}
	err = s.signIn.LinkProvider(ctx, user.ID, string(req.Provider), b.IdToken, b.Nonce, code)
	if err == nil {
		return api.LinkProvider204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.LinkProvider400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.LinkProvider409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) RequestMagicLink(ctx context.Context, req api.RequestMagicLinkRequestObject) (api.RequestMagicLinkResponseObject, error) {
	err := s.signIn.RequestMagicLink(ctx, req.Body.Email, inviteProof(req.Body.Invite), s.magicLinkBase)
	if errors.Is(err, service.ErrMailRateLimited) {
		return api.RequestMagicLink429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.RequestMagicLink400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.RequestMagicLink404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errors.New("no such invitation")))}, nil
		}
		return nil, err
	}
	return api.RequestMagicLink204Response{}, nil
}

func (s *Server) RedeemMagicLink(ctx context.Context, req api.RedeemMagicLinkRequestObject) (api.RedeemMagicLinkResponseObject, error) {
	session, err := s.signIn.RedeemMagicLink(ctx, req.Body.Token)
	if errors.Is(err, service.ErrNoAccount) {
		return api.RedeemMagicLink403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.RedeemMagicLink400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.RedeemMagicLink404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errors.New("the invitation is no longer valid")))}, nil
		}
		return nil, err
	}
	return api.RedeemMagicLink200JSONResponse(signInResult(session)), nil
}
