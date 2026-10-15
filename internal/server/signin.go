package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// signUpProof is the invitation or admission code a request carries, and whether it
// marked itself as a sign-up (with its consent); nil when it carries none of them (a
// plain sign-in). An empty admissionCode and signUp: false count as absent.
func signUpProof(invite *api.InviteProof, code *api.AdmissionCode, signUp *api.SignUp, consent *api.Consent) *service.SignUpProof {
	if code != nil && *code == "" {
		code = nil
	}
	flagged := signUp != nil && *signUp
	if invite == nil && code == nil && !flagged {
		return nil
	}
	p := &service.SignUpProof{SignUp: flagged, Consent: consent != nil && *consent}
	if invite != nil {
		p.Invite = &service.InviteProof{ID: invite.Id, Auth: invite.Auth}
	}
	if code != nil {
		p.AdmissionCode = *code
	}
	return p
}

// errNoSuchProof answers a sign-up whose invitation or admission code is unknown,
// spent, revoked or expired.
var errNoSuchProof = errors.New("no such invitation or admission code")

// errProofGone answers a sign-up whose invitation or admission code stopped being
// valid between the request and its completion.
var errProofGone = errors.New("the invitation or admission code is no longer valid")

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
	b := req.Body
	proof := signUpProof(b.Invite, b.AdmissionCode, b.SignUp, b.Consent)
	if proof == nil {
		proof = &service.SignUpProof{}
	}
	profile := service.SignUpProfile{Username: b.Username, DisplayName: b.DisplayName, Gender: (*string)(b.Gender)}
	c, err := s.signIn.BeginPasskeySignUp(ctx, *proof, profile)
	if errors.Is(err, service.ErrInvitationRequired) {
		return api.BeginPasskeySignUp403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody(err))}, nil
	} else if errors.Is(err, service.ErrSignUpRateLimited) {
		return api.BeginPasskeySignUp429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.BeginPasskeySignUp400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusConflict:
			return api.BeginPasskeySignUp409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.BeginPasskeySignUp404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errNoSuchProof))}, nil
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
	if errors.Is(err, service.ErrInvitationRequired) {
		return api.FinishPasskey403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody(err))}, nil
	} else if errors.Is(err, service.ErrSignUpRateLimited) {
		return api.FinishPasskey429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.FinishPasskey400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusConflict:
			return api.FinishPasskey409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.FinishPasskey404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errProofGone))}, nil
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
	session, err := s.signIn.ProviderSignIn(ctx, string(req.Provider), b.IdToken, b.Nonce, code, signUpProof(b.Invite, b.AdmissionCode, b.SignUp, b.Consent))
	if errors.Is(err, service.ErrNoAccount) || errors.Is(err, service.ErrInvitationRequired) {
		return api.ProviderSignIn403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody(err))}, nil
	} else if errors.Is(err, service.ErrSignUpRateLimited) {
		return api.ProviderSignIn429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.ProviderSignIn400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.ProviderSignIn404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errNoSuchProof))}, nil
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
	b := req.Body
	err := s.signIn.RequestMagicLink(ctx, b.Email, signUpProof(b.Invite, b.AdmissionCode, b.SignUp, b.Consent), s.magicLinkBase)
	if errors.Is(err, service.ErrInvitationRequired) {
		return api.RequestMagicLink403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody(err))}, nil
	}
	if errors.Is(err, service.ErrMailRateLimited) || errors.Is(err, service.ErrSignUpMailRateLimited) {
		return api.RequestMagicLink429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.RequestMagicLink400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.RequestMagicLink404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errNoSuchProof))}, nil
		}
		return nil, err
	}
	return api.RequestMagicLink204Response{}, nil
}

func (s *Server) RedeemMagicLink(ctx context.Context, req api.RedeemMagicLinkRequestObject) (api.RedeemMagicLinkResponseObject, error) {
	var session service.Session
	var err error
	switch b := req.Body; {
	case b.Token != nil && b.Email == nil && b.Code == nil:
		session, err = s.signIn.RedeemMagicLink(ctx, *b.Token)
	case b.Token == nil && b.Email != nil && b.Code != nil:
		session, err = s.signIn.RedeemMagicLinkCode(ctx, *b.Email, *b.Code)
	default:
		return api.RedeemMagicLink400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(errorBody(
			errors.New("send the link's token, or the e-mail address and the code")))}, nil
	}
	if errors.Is(err, service.ErrNoAccount) || errors.Is(err, service.ErrInvitationRequired) {
		return api.RedeemMagicLink403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(errorBody(err))}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.RedeemMagicLink400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.RedeemMagicLink404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errProofGone))}, nil
		}
		return nil, err
	}
	return api.RedeemMagicLink200JSONResponse(signInResult(session)), nil
}

func (s *Server) NewNonce(ctx context.Context, _ api.NewNonceRequestObject) (api.NewNonceResponseObject, error) {
	nonce, err := s.signIn.NewNonce(ctx)
	if err != nil {
		return nil, err
	}
	return api.NewNonce200JSONResponse{Nonce: nonce}, nil
}
