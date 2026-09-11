package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/veops/oneterm/internal/acl"
	"github.com/veops/oneterm/internal/api/router"
	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/internal/schedule"
	"github.com/veops/oneterm/internal/service"
	fileservice "github.com/veops/oneterm/internal/service/file"
	webproxy "github.com/veops/oneterm/internal/service/web_proxy"
	gsession "github.com/veops/oneterm/internal/session"
	"github.com/veops/oneterm/pkg/config"
	"github.com/veops/oneterm/pkg/db"
	"github.com/veops/oneterm/pkg/logger"
)

var (
	ctx, cancel    = context.WithCancel(context.Background())
	srv            = &http.Server{}
	initializeOnce sync.Once
	initializeErr  error
)

func initDB() {
	cfg := db.ConfigFromGlobal()

	if err := db.Init(cfg, true,
		model.DefaultAccount, model.DefaultAsset, model.DefaultAuthorization, model.DefaultAuthorizationV2,
		model.DefaultCommand, model.DefaultCommandTemplate, model.DefaultConfig, model.DefaultFileHistory,
		model.DefaultGateway, model.DefaultHistory, model.DefaultNode, model.DefaultPublicKey,
		model.DefaultSession, model.DefaultSessionCmd, model.DefaultShare, model.DefaultQuickCommand,
		model.DefaultUserPreference, model.DefaultStorageConfig, model.DefaultStorageMetrics,
		model.DefaultTimeTemplate, model.DefaultMigrationRecord, model.DefaultSystemConfig,
		&model.PAMDataKey{}, &model.PAMCredentialVersion{}, &model.PAMAssetAccountBinding{},
		&model.PAMApplication{}, &model.PAMAccessAudit{},
		&model.PAMExecution{},
		&model.PAMPolicy{}, &model.PAMAccessRequest{}, &model.PAMSessionLease{},
	); err != nil {
		logger.L().Fatal("Failed to init database", zap.Error(err))
	}

	if err := db.DropIndex(&model.Authorization{}, "asset_account_id_del"); err != nil {
		logger.L().Fatal("Failed to drop index", zap.Error(err))
	}

	gsession.InitSessionCleanup()
}

func initServices() {
	credentials, err := repository.ConfiguredCredentials()
	if err == nil {
		err = credentials.EnsureDataKey(ctx)
	}
	if err != nil {
		logger.L().Fatal("Failed to initialize credential storage", zap.Error(err))
	}
	if err := service.EnsurePasswordViewPolicy(ctx); err != nil {
		logger.L().Fatal("Failed to initialize password view settings", zap.Error(err))
	}
	service.InitAuthorizationService()
	schedule.RegisterPAMWork(service.ProcessPAMITSMWork)
	fileservice.InitFileService()

	// Initialize predefined dangerous commands and templates
	if err := service.InitBuiltinCommands(); err != nil {
		logger.L().Error("Failed to initialize builtin commands", zap.Error(err))
	}

	// Initialize built-in time templates
	timeTemplateService := service.NewTimeTemplateService()
	if err := timeTemplateService.InitializeBuiltInTemplates(ctx); err != nil {
		logger.L().Error("Failed to initialize built-in time templates", zap.Error(err))
	}

	acl.MigrateNode()
	acl.MigrateCommand()
}

func initStorage() error {
	service.InitStorageService()

	if service.DefaultStorageService == nil {
		logger.L().Error("Storage service initialization failed")
		return nil
	}

	logger.L().Info("Storage system initialization completed successfully")

	// Initialize storage cleaner service
	service.InitStorageCleanerService()

	return nil
}

func Initialize() error {
	initializeOnce.Do(func() {
		initDB()
		initServices()
		initializeErr = initStorage()
	})
	return initializeErr
}

func RunApi() error {
	if err := Initialize(); err != nil {
		return err
	}

	r := gin.New()

	router.SetupRouter(r)

	srv.Addr = fmt.Sprintf("%s:%d", config.Cfg.Http.Host, config.Cfg.Http.Port)
	srv.Handler = r

	logger.L().Info("Starting HTTP server",
		zap.String("address", srv.Addr))

	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		logger.L().Fatal("Start HTTP server failed", zap.Error(err))
	}

	return err
}

func StopApi() {
	defer cancel()

	logger.L().Info("Stopping HTTP server")
	if err := srv.Shutdown(ctx); err != nil {
		logger.L().Error("Stop HTTP server failed", zap.Error(err))
	}

	// Stop storage service background tasks
	service.StopStorageService()

	// Stop web proxy session cleanup routine
	webproxy.StopSessionCleanupRoutine()
}
