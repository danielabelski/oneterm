package connector

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/veops/oneterm/internal/service"
	fileservice "github.com/veops/oneterm/internal/service/file"
	gsession "github.com/veops/oneterm/internal/session"
	apiErrors "github.com/veops/oneterm/pkg/errors"
	"github.com/veops/oneterm/pkg/logger"
)

func pamConnectionError(err error) error {
	var problem *apiErrors.ApiError
	if errors.As(err, &problem) {
		return problem
	}
	code := apiErrors.ErrPAMUnavailable
	switch {
	case errors.Is(err, service.ErrPAMInput):
		code = apiErrors.ErrPAMInput
	case errors.Is(err, service.ErrPAMDenied):
		code = apiErrors.ErrPAMDenied
	case errors.Is(err, service.ErrPAMScopeChanged):
		code = apiErrors.ErrPAMScopeChanged
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		code = apiErrors.ErrPAMSessionEnded
	}
	return &apiErrors.ApiError{Code: code}
}

func waitPAMConnection(ctx context.Context, sess *gsession.Session) error {
	deadline := sess.PAMAuthorization.LeaseExpiresAt
	if grantDeadline := sess.PAMAuthorization.Deadline; grantDeadline != nil && grantDeadline.Before(deadline) {
		deadline = *grantDeadline
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-sess.Chans.ErrChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return &apiErrors.ApiError{Code: apiErrors.ErrPAMSessionEnded}
	}
}

func stopPAMConnection(sess *gsession.Session) {
	sess.Once.Do(func() { close(sess.Chans.AwayChan) })
	sess.ClosePAMTransport()
	if sess.Ws != nil {
		sess.Ws.Close()
	}
	if fileservice.DefaultFileService != nil {
		fileservice.DefaultFileService.CloseSessionFileClient(sess.SessionId)
	}
}

func releasePAMConnection(sess *gsession.Session) {
	if err := service.ReleasePAMConnection(sess.Gctx, sess.PAMAuthorization); err != nil {
		logger.L().Warn("Failed to release PAM session admission", zap.String("session_id", sess.SessionId), zap.Error(err))
	}
}
