package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/auth"
	"github.com/Duongondro/duongondro-api/internal/db"
	"github.com/Duongondro/duongondro-api/internal/repository"
	"github.com/Duongondro/duongondro-api/internal/service"
)

// Each handler authenticates first and answers 401 for a missing or revoked token,
// then maps service errors with clientError; anything else is a 500.

func (s *Server) GetMe(ctx context.Context, req api.GetMeRequestObject) (api.GetMeResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.GetMe401Response{}, nil
	}
	devices, err := s.devices.List(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	me := api.GetMe200JSONResponse{Id: user.ID, KeyVersion: int(user.KeyVersion), DisplayName: user.DisplayName, Devices: deviceDTOs(devices)}
	if user.IdentityPublicKey != nil {
		me.IdentityPublicKey = &user.IdentityPublicKey
	}
	return me, nil
}

func (s *Server) SignOut(ctx context.Context, req api.SignOutRequestObject) (api.SignOutResponseObject, error) {
	token, ok := auth.BearerPrefix(req.Params.Authorization)
	if !ok {
		return api.SignOut401Response{}, nil
	}
	revoked, err := s.auth.RevokeToken(ctx, token)
	if err != nil {
		return nil, err
	} else if !revoked {
		return api.SignOut401Response{}, nil
	}
	return api.SignOut204Response{}, nil
}

func (s *Server) PutIdentity(ctx context.Context, req api.PutIdentityRequestObject) (api.PutIdentityResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutIdentity401Response{}, nil
	}
	err = s.accounts.SetIdentity(ctx, user, req.Body.PublicKey)
	if err == nil {
		return api.PutIdentity204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.PutIdentity400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.PutIdentity409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) GetDeviceList(ctx context.Context, req api.GetDeviceListRequestObject) (api.GetDeviceListResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.GetDeviceList401Response{}, nil
	}
	list, err := s.devices.DeviceList(ctx, user.ID)
	if errors.Is(err, service.ErrNotFound) {
		return api.GetDeviceList404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(errors.New("no device list published yet")))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.GetDeviceList200JSONResponse{Payload: list.Payload, Signature: list.Signature}, nil
}

func (s *Server) PutDeviceList(ctx context.Context, req api.PutDeviceListRequestObject) (api.PutDeviceListResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutDeviceList401Response{}, nil
	}
	err = s.devices.PutDeviceList(ctx, user, req.Body.Payload, req.Body.Signature)
	if err == nil {
		return api.PutDeviceList204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.PutDeviceList400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.PutDeviceList409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) RotatePracticeKey(ctx context.Context, req api.RotatePracticeKeyRequestObject) (api.RotatePracticeKeyResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.RotatePracticeKey401Response{}, nil
	}
	wraps := make([]service.RotationWrap, len(req.Body.Wraps))
	for i, w := range req.Body.Wraps {
		wraps[i] = service.RotationWrap{DeviceID: w.DeviceId, WrapInput: service.WrapInput{
			Kind: w.Kind, KeyVersion: w.KeyVersion, EphemeralKey: w.EphemeralKey, Box: w.Box,
			AuthType: string(w.AuthType), Authenticator: w.Authenticator,
		}}
	}
	err = s.wraps.Rotate(ctx, user, req.Body.NewVersion, wraps)
	if errors.Is(err, repository.ErrStaleRotation) {
		return api.RotatePracticeKey409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(errorBody(err))}, nil
	}
	if err == nil {
		return api.RotatePracticeKey204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	case ok && kind == http.StatusBadRequest:
		return api.RotatePracticeKey400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusConflict:
		return api.RotatePracticeKey409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) ListRecoveryBoxes(ctx context.Context, req api.ListRecoveryBoxesRequestObject) (api.ListRecoveryBoxesResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ListRecoveryBoxes401Response{}, nil
	}
	boxes, err := s.recovery.List(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	out := api.ListRecoveryBoxes200JSONResponse{Boxes: make([]api.RecoveryBox, len(boxes))}
	for i, b := range boxes {
		out.Boxes[i] = api.RecoveryBox{Kind: int(b.Kind), Box: b.Box, UpdatedAt: b.UpdatedAt}
	}
	return out, nil
}

func (s *Server) PutRecoveryBox(ctx context.Context, req api.PutRecoveryBoxRequestObject) (api.PutRecoveryBoxResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutRecoveryBox401Response{}, nil
	}
	err = s.recovery.Put(ctx, user.ID, int(req.Kind), req.Body.Box)
	if err == nil {
		return api.PutRecoveryBox204Response{}, nil
	}
	if kind, body, ok := clientError(err); ok && kind == http.StatusBadRequest {
		return api.PutRecoveryBox400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) ListDevices(ctx context.Context, req api.ListDevicesRequestObject) (api.ListDevicesResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ListDevices401Response{}, nil
	}
	devices, err := s.devices.List(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return api.ListDevices200JSONResponse{Devices: deviceDTOs(devices)}, nil
}

func (s *Server) RegisterDevice(ctx context.Context, req api.RegisterDeviceRequestObject) (api.RegisterDeviceResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.RegisterDevice401Response{}, nil
	}
	dev, created, err := s.devices.Register(ctx, user.ID, req.Body.PublicKey, string(req.Body.Tier))
	if err != nil {
		if kind, body, ok := clientError(err); ok && kind == http.StatusBadRequest {
			return api.RegisterDevice400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		}
		return nil, err
	}
	if created {
		return api.RegisterDevice201JSONResponse(deviceDTO(dev)), nil
	}
	return api.RegisterDevice200JSONResponse(deviceDTO(dev)), nil
}

func (s *Server) DeleteDevice(ctx context.Context, req api.DeleteDeviceRequestObject) (api.DeleteDeviceResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.DeleteDevice401Response{}, nil
	}
	err = s.devices.Delete(ctx, user.ID, req.DeviceId)
	if errors.Is(err, service.ErrNotFound) {
		return api.DeleteDevice404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	return api.DeleteDevice204Response{}, nil
}

func (s *Server) ListWraps(ctx context.Context, req api.ListWrapsRequestObject) (api.ListWrapsResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ListWraps401Response{}, nil
	}
	wraps, err := s.wraps.List(ctx, user.ID, req.DeviceId)
	if errors.Is(err, service.ErrNotFound) {
		return api.ListWraps404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(errorBody(err))}, nil
	} else if err != nil {
		return nil, err
	}
	out := api.ListWraps200JSONResponse{Wraps: make([]api.Wrap, len(wraps))}
	for i, w := range wraps {
		out.Wraps[i] = api.Wrap{
			DeviceId: w.DeviceID, Kind: int(w.Kind), KeyVersion: int(w.KeyVersion), EphemeralKey: w.EphemeralKey,
			Box: w.Box, AuthType: api.AuthType(w.AuthType), Authenticator: w.Authenticator, CreatedAt: w.CreatedAt,
		}
	}
	return out, nil
}

func (s *Server) PutWrap(ctx context.Context, req api.PutWrapRequestObject) (api.PutWrapResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutWrap401Response{}, nil
	}
	b := req.Body
	err = s.wraps.Put(ctx, user, req.DeviceId, service.WrapInput{
		Kind: b.Kind, KeyVersion: b.KeyVersion, EphemeralKey: b.EphemeralKey, Box: b.Box,
		AuthType: string(b.AuthType), Authenticator: b.Authenticator,
	})
	if err == nil {
		return api.PutWrap204Response{}, nil
	}
	switch kind, body, ok := clientError(err); {
	// A missing identity key is a conflict in the service; for a wrap it is a request
	// the client must fix first, answered 400.
	case ok && (kind == http.StatusBadRequest || kind == http.StatusConflict):
		return api.PutWrap400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	case ok && kind == http.StatusNotFound:
		return api.PutWrap404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
	}
	return nil, err
}

func (s *Server) PutPracticeLog(ctx context.Context, req api.PutPracticeLogRequestObject) (api.PutPracticeLogResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.PutPracticeLog401Response{}, nil
	}
	b := req.Body
	in := service.LogInput{KeyVersion: b.KeyVersion, UpdatedAt: b.UpdatedAt, Deleted: b.Deleted != nil && *b.Deleted}
	if b.Sealed != nil {
		in.Sealed = *b.Sealed
	}
	row, err := s.logs.Put(ctx, user, req.LogId, in)
	if old, is := errors.AsType[*service.OldKeyError](err); is {
		return api.PutPracticeLog422JSONResponse{Error: old.Error(), CurrentKeyVersion: old.Current}, nil
	}
	if err != nil {
		switch kind, body, ok := clientError(err); {
		case ok && kind == http.StatusBadRequest:
			return api.PutPracticeLog400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		case ok && kind == http.StatusNotFound:
			return api.PutPracticeLog404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(body)}, nil
		}
		return nil, err
	}
	return api.PutPracticeLog200JSONResponse(logDTO(row)), nil
}

func (s *Server) Sync(ctx context.Context, req api.SyncRequestObject) (api.SyncResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.Sync401Response{}, nil
	}
	since := ""
	if req.Params.Since != nil {
		since = *req.Params.Since
	}
	changes, err := s.logs.Sync(ctx, user.ID, since)
	if err != nil {
		if kind, body, ok := clientError(err); ok && kind == http.StatusBadRequest {
			return api.Sync400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
		}
		return nil, err
	}
	out := api.Sync200JSONResponse{Cursor: service.FormatCursor(changes.Cursor), Full: changes.Full, Logs: make([]api.PracticeLog, len(changes.Logs))}
	for i, l := range changes.Logs {
		out.Logs[i] = logDTO(l)
	}
	return out, nil
}

func deviceDTO(d db.Device) api.Device {
	return api.Device{Id: d.ID, PublicKey: d.PublicKey, Tier: api.Tier(d.Tier), CreatedAt: d.CreatedAt}
}

func deviceDTOs(ds []db.Device) []api.Device {
	out := make([]api.Device, len(ds))
	for i, d := range ds {
		out[i] = deviceDTO(d)
	}
	return out
}

func logDTO(l db.PracticeLog) api.PracticeLog {
	out := api.PracticeLog{Id: l.ID, KeyVersion: int(l.KeyVersion), UpdatedAt: l.ClientUpdatedAt, DeletedAt: l.DeletedAt}
	if l.Sealed != nil {
		out.Sealed = &l.Sealed
	}
	return out
}
