package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/service"
)

func (s *Server) UpdateMe(ctx context.Context, req api.UpdateMeRequestObject) (api.UpdateMeResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.UpdateMe401Response{}, nil
	}
	if err := s.social.SetDisplayName(ctx, user.ID, req.Body.DisplayName); err != nil {
		if kind, body, ok := clientError(err); ok && kind == http.StatusBadRequest {
			return api.UpdateMe400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.UpdateMe204Response{}, nil
}

func (s *Server) DeleteMe(ctx context.Context, req api.DeleteMeRequestObject) (api.DeleteMeResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.DeleteMe401Response{}, nil
	}
	// Apple requires the authorisation revoked; the refresh tokens go with the purge.
	s.signIn.RevokeApple(ctx, user.ID)
	if err := s.gdpr.Purge(ctx, user.ID); err != nil && !errors.Is(err, service.ErrNotFound) {
		return nil, err
	}
	return api.DeleteMe204Response{}, nil
}

func (s *Server) ExportMe(ctx context.Context, req api.ExportMeRequestObject) (api.ExportMeResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ExportMe401Response{}, nil
	}
	export, err := s.gdpr.Export(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	// Through JSON, so the response has exactly Export's keys and encodings.
	raw, err := json.Marshal(export)
	if err != nil {
		return nil, err
	}
	var out api.ExportMe200JSONResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) ListInvites(ctx context.Context, req api.ListInvitesRequestObject) (api.ListInvitesResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ListInvites401Response{}, nil
	}
	invites, err := s.social.Invites(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	out := api.ListInvites200JSONResponse{Invites: make([]api.InviteSummary, len(invites))}
	for i, inv := range invites {
		out.Invites[i] = api.InviteSummary{Id: inv.ID, ExpiresAt: inv.ExpiresAt, RevokedAt: inv.RevokedAt, CreatedAt: inv.CreatedAt}
	}
	return out, nil
}

func (s *Server) CreateInvite(ctx context.Context, req api.CreateInviteRequestObject) (api.CreateInviteResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.CreateInvite401Response{}, nil
	}
	b := req.Body
	err = s.social.CreateInvite(ctx, user, b.Id, b.Auth, b.ExpiresAt, b.Payload, b.Signature, b.Mac)
	if err == nil {
		return api.CreateInvite201Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.CreateInvite400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.CreateInvite409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) GetInvite(ctx context.Context, req api.GetInviteRequestObject) (api.GetInviteResponseObject, error) {
	inv, err := s.social.Invite(ctx, req.InviteId)
	if errors.Is(err, service.ErrNotFound) {
		return api.GetInvite404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.GetInvite200JSONResponse{Id: inv.ID, Payload: inv.Payload, Signature: inv.Signature, Mac: inv.Mac, ExpiresAt: inv.ExpiresAt}, nil
}

func (s *Server) RevokeInvite(ctx context.Context, req api.RevokeInviteRequestObject) (api.RevokeInviteResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.RevokeInvite401Response{}, nil
	}
	err = s.social.RevokeInvite(ctx, user.ID, req.InviteId)
	if errors.Is(err, service.ErrNotFound) {
		return api.RevokeInvite404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.RevokeInvite204Response{}, nil
}

func (s *Server) RedeemInvite(ctx context.Context, req api.RedeemInviteRequestObject) (api.RedeemInviteResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.RedeemInvite401Response{}, nil
	}
	b := req.Body
	inviter, err := s.social.Redeem(ctx, user, req.InviteId, b.Auth, b.Acceptance.Payload, b.Acceptance.Signature)
	if err == nil {
		return api.RedeemInvite200JSONResponse{InviterId: inviter}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.RedeemInvite400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusNotFound:
		return api.RedeemInvite404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.RedeemInvite409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) ListFriends(ctx context.Context, req api.ListFriendsRequestObject) (api.ListFriendsResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ListFriends401Response{}, nil
	}
	friends, err := s.social.Friends(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	out := api.ListFriends200JSONResponse{Friends: make([]api.Friend, len(friends))}
	for i, f := range friends {
		out.Friends[i] = api.Friend{UserId: f.ID, DisplayName: f.DisplayName, Since: f.CreatedAt}
		if f.IdentityPublicKey != nil {
			key := f.IdentityPublicKey
			out.Friends[i].IdentityPublicKey = &key
		}
	}
	return out, nil
}

func (s *Server) Unfriend(ctx context.Context, req api.UnfriendRequestObject) (api.UnfriendResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.Unfriend401Response{}, nil
	}
	err = s.social.Unfriend(ctx, user.ID, req.UserId)
	if errors.Is(err, service.ErrNotFound) {
		return api.Unfriend404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.Unfriend204Response{}, nil
}

func (s *Server) ListBlocks(ctx context.Context, req api.ListBlocksRequestObject) (api.ListBlocksResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ListBlocks401Response{}, nil
	}
	blocks, err := s.social.Blocks(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	out := api.ListBlocks200JSONResponse{Blocks: make([]api.BlockEntry, len(blocks))}
	for i, b := range blocks {
		out.Blocks[i] = api.BlockEntry{UserId: b.BlockedID, CreatedAt: b.CreatedAt}
	}
	return out, nil
}

func (s *Server) Block(ctx context.Context, req api.BlockRequestObject) (api.BlockResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.Block401Response{}, nil
	}
	err = s.social.Block(ctx, user.ID, req.UserId)
	if err == nil {
		return api.Block204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.Block400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusNotFound:
		return api.Block404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) Unblock(ctx context.Context, req api.UnblockRequestObject) (api.UnblockResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.Unblock401Response{}, nil
	}
	err = s.social.Unblock(ctx, user.ID, req.UserId)
	if errors.Is(err, service.ErrNotFound) {
		return api.Unblock404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.Unblock204Response{}, nil
}

func (s *Server) Report(ctx context.Context, req api.ReportRequestObject) (api.ReportResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.Report401Response{}, nil
	}
	id, err := s.social.Report(ctx, user.ID, req.Body.UserId, req.Body.Reason)
	if err == nil {
		return api.Report201JSONResponse{Id: id}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.Report400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusNotFound:
		return api.Report404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) OwnStreaks(ctx context.Context, req api.OwnStreaksRequestObject) (api.OwnStreaksResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.OwnStreaks401Response{}, nil
	}
	streaks, err := s.social.OwnStreaks(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return api.OwnStreaks200JSONResponse(streakList(streaks)), nil
}

func (s *Server) FriendsStreaks(ctx context.Context, req api.FriendsStreaksRequestObject) (api.FriendsStreaksResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.FriendsStreaks401Response{}, nil
	}
	streaks, err := s.social.FriendsStreaks(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return api.FriendsStreaks200JSONResponse(streakList(streaks)), nil
}

func (s *Server) PutStreak(ctx context.Context, req api.PutStreakRequestObject) (api.PutStreakResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutStreak401Response{}, nil
	}
	err = s.social.PutStreak(ctx, user, req.Practice, req.Body.Payload, req.Body.Signature)
	if err == nil {
		return api.PutStreak204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.PutStreak400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.PutStreak409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) DeleteStreak(ctx context.Context, req api.DeleteStreakRequestObject) (api.DeleteStreakResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.DeleteStreak401Response{}, nil
	}
	err = s.social.DeleteStreak(ctx, user.ID, req.Practice)
	if errors.Is(err, service.ErrNotFound) {
		return api.DeleteStreak404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.DeleteStreak204Response{}, nil
}

func streakList(streaks []db.Streak) api.StreakList {
	out := api.StreakList{Streaks: make([]api.StreakStatement, len(streaks))}
	for i, st := range streaks {
		out.Streaks[i] = api.StreakStatement{UserId: st.UserID, Practice: st.Practice, Payload: st.Payload, Signature: st.Signature}
	}
	return out
}
