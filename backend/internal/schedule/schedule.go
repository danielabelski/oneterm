package schedule

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/pkg/logger"
	"go.uber.org/zap"
)

var (
	ctx, cancel    = context.WithCancel(context.Background())
	scheduleConfig = model.GetDefaultScheduleConfig()
	pamWork        func(context.Context, int) error
)

func RegisterPAMWork(worker func(context.Context, int) error) { pamWork = worker }

func init() {
	UpdateConfig()
}

func RunSchedule() (err error) {
	logger.L().Info("Starting scheduler with configuration",
		zap.Duration("connectable_check_interval", scheduleConfig.ConnectableCheckInterval),
		zap.Duration("config_update_interval", scheduleConfig.ConfigUpdateInterval),
		zap.Int("batch_size", scheduleConfig.BatchSize),
		zap.Int("concurrent_workers", scheduleConfig.ConcurrentWorkers))

	connectableTicker := time.NewTicker(scheduleConfig.ConnectableCheckInterval)
	pamTicker := time.NewTicker(15 * time.Second)
	var pamRunning atomic.Bool
	// configTicker := time.NewTicker(scheduleConfig.ConfigUpdateInterval)

	defer connectableTicker.Stop()
	defer pamTicker.Stop()
	// defer configTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L().Info("Scheduler stopped")
			return
		case <-pamTicker.C:
			if pamWork != nil && pamRunning.CompareAndSwap(false, true) {
				go func() {
					defer pamRunning.Store(false)
					if err := pamWork(ctx, 20); err != nil {
						logger.L().Warn("PAM ITSM work requires retry", zap.Error(err))
					}
				}()
			}
		case <-connectableTicker.C:
			go func() {
				if err := UpdateConnectables(); err != nil {
					logger.L().Error("Failed to update connectables", zap.Error(err))
				}
			}()
			// case <-configTicker.C:
			// 	UpdateConfig()
		}
	}
}

func StopSchedule() {
	defer cancel()
	logger.L().Info("Stopping scheduler")
}
