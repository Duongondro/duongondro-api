package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/Duongondro/duongondro-api/internal/api"
	"github.com/Duongondro/duongondro-api/internal/service"
)

func (s *Server) ReportClientError(ctx context.Context, req api.ReportClientErrorRequestObject) (api.ReportClientErrorResponseObject, error) {
	user, ok, err := s.authenticate(ctx, req.Params.Authorization)
	if err != nil {
		return nil, err
	} else if !ok {
		return api.ReportClientError401Response{}, nil
	}
	b := req.Body
	r := service.ClientErrorReport{Crash: b.Kind == api.ClientErrorReportKindCrash, Message: b.Message}
	if b.AppVersion != nil {
		r.AppVersion = *b.AppVersion
	}
	if b.OsVersion != nil {
		r.OSVersion = *b.OsVersion
	}
	if b.Context != nil {
		r.Context = *b.Context
	}
	err = s.clientErrors.Report(ctx, user.ID, r)
	switch {
	case err == nil:
		return api.ReportClientError204Response{}, nil
	case errors.Is(err, service.ErrReportsRateLimited):
		return api.ReportClientError429JSONResponse{TooManyRequestsJSONResponse: api.TooManyRequestsJSONResponse(errorBody(err))}, nil
	}
	if kind, body, ok := clientError(err); ok && kind == http.StatusBadRequest {
		return api.ReportClientError400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(body)}, nil
	}
	return nil, err
}
