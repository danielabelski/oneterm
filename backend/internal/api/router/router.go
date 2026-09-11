package router

import (
	"strings"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/veops/oneterm/internal/api/controller"
	"github.com/veops/oneterm/internal/api/docs"
	"github.com/veops/oneterm/internal/api/middleware"
	"github.com/veops/oneterm/internal/sshsrv"
	"github.com/veops/oneterm/pkg/config"
)

func SetupRouter(r *gin.Engine) {
	if err := middleware.ConfigureTrustedProxies(r, config.Cfg.Http.TrustedProxies); err != nil {
		panic(err)
	}
	r.MaxMultipartMemory = 1 << 20 // 1MB to prevent memory overflow
	r.Use(gin.Recovery(), middleware.LoggerMiddleware())

	// Start web session cleanup routine
	controller.StartSessionCleanupRoutine()

	webProxy := controller.NewWebProxyController()
	r.Use(func(c *gin.Context) {
		host := c.Request.Host

		// Check if this is the webproxy subdomain request
		if strings.HasPrefix(host, "webproxy.") {
			if strings.HasPrefix(c.Request.URL.Path, "/api/oneterm/v1/") {
				c.Next()
				return
			}

			if c.Request.URL.Path == "/external" {
				webProxy.HandleExternalRedirect(c)
				return
			}

			webProxy.ProxyWebRequest(c)
			return
		}

		c.Next()
	})

	docs.SwaggerInfo.Title = "ONETERM API"
	docs.SwaggerInfo.BasePath = "/api/oneterm/v1"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	c := controller.Controller{}

	v1 := r.Group("/api/oneterm/v1", middleware.Error2RespMiddleware(), middleware.AuthMiddleware())
	v1AuthAbandoned := r.Group("/api/oneterm/v1", middleware.Error2RespMiddleware())
	v1AuthAbandoned.POST("/pam/application/credentials", c.RetrievePAMApplicationCredential)
	v1.GET("/pam/applications", c.GetPAMApplications)
	v1.POST("/pam/applications", c.CreatePAMApplication)
	v1.PUT("/pam/applications/:id", c.UpdatePAMApplication)
	v1.POST("/pam/applications/:id/disable", c.DisablePAMApplication)
	v1.GET("/pam/targets", c.GetPAMTargets)
	v1.GET("/pam/capabilities", c.GetPAMCapabilities)
	v1.GET("/config/password-view", c.GetPasswordViewSettings)
	v1.PUT("/config/password-view", c.SavePasswordViewSettings)
	v1.GET("/pam/password-view/accounts", c.GetPasswordViewAccounts)
	v1.GET("/pam/password-view/audit", c.GetPasswordViewAudit)
	v1.GET("/pam/password-view/:kind/:id", c.GetPasswordViewStatus)
	v1.POST("/pam/password-view/:kind/:id/requests", c.CreatePasswordViewRequest)
	v1.POST("/pam/password-view/:kind/:id/read", c.ReadPasswordView)
	v1.GET("/pam/itsm/templates", c.GetPAMITSMTemplates)
	v1.GET("/pam/itsm/templates/:id", c.GetPAMITSMTemplate)
	v1.GET("/pam/policies/:kind/:id", c.GetPAMPolicy)
	v1.PUT("/pam/policies/:kind/:id", c.SavePAMPolicy)
	v1.GET("/pam/requests", c.GetPAMRequests)
	v1.GET("/pam/request-targets", c.GetPAMRequestTargets)
	v1.GET("/pam/request-targets/:id/bindings", c.GetPAMRequestBindings)
	v1.POST("/pam/requests", c.CreatePAMRequest)
	v1.GET("/pam/requests/:id", c.GetPAMRequest)
	v1.POST("/pam/requests/:id/cancel", c.CancelPAMRequest)
	v1.POST("/pam/requests/:id/retry-sync", c.RetryPAMRequestSync)
	v1.GET("/pam/adoption/assets", c.GetPAMAdoptionAssets)
	v1.GET("/pam/accounts/:id", c.GetPAMAccount)
	v1.POST("/pam/accounts/adopt", c.AdoptPAMAccount)
	v1.GET("/pam/accounts/:id/bindings", c.GetPAMAccountBindings)
	v1.POST("/pam/accounts/:id/bindings", c.AttachPAMAccount)
	v1.PUT("/pam/accounts/:id/bindings", c.ReviewPAMBinding)
	v1.PUT("/pam/accounts/:id/bindings/:binding_id/password", c.SavePAMPasswordConfig)
	v1.GET("/pam/accounts/:id/password/executors", c.GetPAMPasswordExecutors)
	v1.POST("/pam/accounts/:id/password/verify", c.VerifyPAMPassword)
	v1.GET("/pam/accounts/:id/password/executions", c.GetPAMPasswordExecutions)
	v1.POST("/pam/accounts/:id/password/executions", c.StartPAMPasswordChange)
	v1.POST("/pam/accounts/:id/password/executions/:execution_id/:operation", c.ContinuePAMPassword)
	v1.POST("/pam/accounts/:id/disable", c.DisablePAMAccount)
	v1.POST("/pam/accounts/:id/enable", c.EnablePAMAccount)
	v1.DELETE("/pam/accounts/:id/management", c.RemovePAMAccountManagement)
	v1.POST("/pam/credentials/:kind/:id", c.RetrievePAMHumanCredential)
	v1.GET("/pam/audit", c.GetPAMAccessAudit)
	{
		account := v1.Group("account")
		{
			account.POST("", c.CreateAccount)
			account.DELETE("/:id", c.DeleteAccount)
			account.PUT("/:id", c.UpdateAccount)
			account.GET("", c.GetAccounts)
			account.POST("/:id/credentials", c.GetAccountCredentials)
			account.GET("/:id/credentials2", c.GetAccountCredentials2)
		}

		asset := v1.Group("asset")
		{
			asset.POST("", c.CreateAsset)
			asset.DELETE("/:id", c.DeleteAsset)
			asset.PUT("/:id", c.UpdateAsset)
			asset.GET("", c.GetAssets)
			asset.GET("/:id/permissions", c.GetAssetPermissions)
		}

		node := v1.Group("node")
		{
			node.POST("", c.CreateNode)
			node.DELETE("/:id", c.DeleteNode)
			node.PUT("/:id", c.UpdateNode)
			node.GET("", c.GetNodes)
		}

		publicKey := v1.Group("public_key")
		{
			publicKey.POST("", c.CreatePublicKey)
			publicKey.DELETE("/:id", c.DeletePublicKey)
			publicKey.PUT("/:id", c.UpdatePublicKey)
			publicKey.GET("", c.GetPublicKeys)
		}

		gateway := v1.Group("gateway")
		{
			gateway.POST("", c.CreateGateway)
			gateway.DELETE("/:id", c.DeleteGateway)
			gateway.PUT("/:id", c.UpdateGateway)
			gateway.GET("", c.GetGateways)
		}

		stat := v1.Group("stat")
		{
			stat.GET("assettype", c.StatAssetType)
			stat.GET("count", c.StatCount)
			stat.GET("count/ofuser", c.StatCountOfUser)
			stat.GET("account", c.StatAccount)
			stat.GET("asset", c.StatAsset)
			stat.GET("rank/ofuser", c.StatRankOfUser)
		}

		command := v1.Group("command")
		{
			command.POST("", c.CreateCommand)
			command.DELETE("/:id", c.DeleteCommand)
			command.PUT("/:id", c.UpdateCommand)
			command.GET("", c.GetCommands)
		}

		session := v1.Group("session")
		{
			session.GET("", c.GetSessions)
			session.GET("/:session_id/cmd", c.GetSessionCmds)
			session.GET("/option/asset", c.GetSessionOptionAsset)
			session.GET("/option/clientip", c.GetSessionOptionClientIp)
			session.GET("/replay/:session_id", c.GetSessionReplay)
		}

		connect := v1.Group("connect")
		{
			connect.GET("/:asset_id/:account_id/:protocol", c.Connect)
			connect.GET("/monitor/:session_id", c.ConnectMonitor)
			connect.POST("/close/:session_id", c.ConnectClose)
			// WebSSH route - direct access to SSH server interface
			connect.GET("/webssh", sshsrv.HandleWebSSH)
		}

		file := v1.Group("file")
		{
			file.GET("/history", c.GetFileHistory)

			// Legacy asset-based file operations (for backward compatibility)
			file.GET("/ls/:asset_id/:account_id", c.FileLS)
			file.POST("/mkdir/:asset_id/:account_id", c.FileMkdir)
			file.POST("/upload/:asset_id/:account_id", c.FileUpload)
			file.GET("/download/:asset_id/:account_id", c.FileDownload)

			sftpFile := file.Group("/session/:session_id")
			{
				sftpFile.GET("/ls", c.SftpFileLS)
				sftpFile.POST("/mkdir", c.SftpFileMkdir)
				sftpFile.POST("/upload", c.SftpFileUpload)
				sftpFile.GET("/download", c.SftpFileDownload)
			}

			// File transfer progress tracking
			file.GET("/transfer/progress/id/:transfer_id", c.TransferProgressById)
		}

		config := v1.Group("config")
		{
			config.POST("", c.PostConfig)
		}
		config2 := v1AuthAbandoned.Group("config")
		{
			config2.GET("", c.GetConfig)
		}

		history := v1.Group("history")
		{
			history.GET("", c.GetHistories)
			history.GET("/type/mapping", c.GetHistoryTypeMapping)
		}

		share := v1.Group("/share")
		{
			share.POST("", c.CreateShare)
			share.DELETE("/:id", c.DeleteShare)
			share.GET("", c.GetShare)
		}

		r.GET("/api/oneterm/v1/share/connect/:uuid", middleware.Error2RespMiddleware(), c.ConnectShare)

		authorization := v1.Group("/authorization")
		{
			authorization.POST("", c.UpsertAuthorization)
			authorization.DELETE("/:id", c.DeleteAuthorization)
			authorization.GET("", c.GetAuthorizations)
		}

		authorizationV2 := v1.Group("/authorization_v2")
		{
			authorizationV2.POST("", c.CreateAuthorizationV2)
			authorizationV2.GET("", c.GetAuthorizationsV2)
			authorizationV2.GET("/:id", c.GetAuthorizationV2)
			authorizationV2.PUT("/:id", c.UpdateAuthorizationV2)
			authorizationV2.DELETE("/:id", c.DeleteAuthorizationV2)
			authorizationV2.POST("/:id/clone", c.CloneAuthorizationV2)
			authorizationV2.POST("/check", c.CheckPermissionV2)
		}

		quickCommand := v1.Group("/quick_command")
		{
			quickCommand.POST("", c.CreateQuickCommand)
			quickCommand.GET("", c.GetQuickCommands)
			quickCommand.DELETE("/:id", c.DeleteQuickCommand)
			quickCommand.PUT("/:id", c.UpdateQuickCommand)
		}

		preference := v1.Group("/preference")
		{
			preference.GET("", c.GetPreference)
			preference.PUT("", c.UpdatePreference)
		}

		// RDP file transfer routes
		rdpGroup := v1.Group("/rdp")
		{
			rdpGroup.GET("/sessions/:session_id/files", c.RDPFileList)
			rdpGroup.POST("/sessions/:session_id/files/upload", c.RDPFileUpload)
			rdpGroup.GET("/sessions/:session_id/files/download", c.RDPFileDownload)
			rdpGroup.POST("/sessions/:session_id/files/mkdir", c.RDPFileMkdir)
		}

		// Storage management routes
		storage := v1.Group("/storage")
		{
			storage.GET("/configs", c.ListStorageConfigs)
			storage.GET("/configs/:id", c.GetStorageConfig)
			storage.POST("/configs", c.CreateStorageConfig)
			storage.PUT("/configs/:id", c.UpdateStorageConfig)
			storage.DELETE("/configs/:id", c.DeleteStorageConfig)
			storage.POST("/test-connection", c.TestStorageConnection)
			storage.GET("/health", c.GetStorageHealth)
			// storage.GET("/metrics", c.GetStorageMetrics)
			// storage.POST("/metrics/refresh", c.RefreshStorageMetrics)
			storage.PUT("/configs/:id/set-primary", c.SetPrimaryStorage)
			storage.PUT("/configs/:id/toggle", c.ToggleStorageProvider)
		}

		// Time template management routes
		timeTemplate := v1.Group("/time_template")
		{
			timeTemplate.POST("", c.CreateTimeTemplate)
			timeTemplate.DELETE("/:id", c.DeleteTimeTemplate)
			timeTemplate.PUT("/:id", c.UpdateTimeTemplate)
			timeTemplate.GET("", c.GetTimeTemplates)
			timeTemplate.GET("/builtin", c.GetBuiltInTimeTemplates)
			timeTemplate.POST("/check", c.CheckTimeAccess)
			timeTemplate.POST("/init", c.InitBuiltInTemplates)
		}

		// Command template management routes
		commandTemplate := v1.Group("/command_template")
		{
			commandTemplate.POST("", c.CreateCommandTemplate)
			commandTemplate.DELETE("/:id", c.DeleteCommandTemplate)
			commandTemplate.PUT("/:id", c.UpdateCommandTemplate)
			commandTemplate.GET("", c.GetCommandTemplates)
			commandTemplate.GET("/builtin", c.GetBuiltInCommandTemplates)
			commandTemplate.GET("/:id/commands", c.GetTemplateCommands)
		}

		// Web proxy management API routes
		webProxyGroup := v1.Group("/web_proxy")
		{
			webProxyGroup.GET("/config/:asset_id", webProxy.GetWebAssetConfig)
			webProxyGroup.POST("/start", webProxy.StartWebSession)
			webProxyGroup.GET("/external_redirect", webProxy.HandleExternalRedirect)
			webProxyGroup.POST("/close", webProxy.CloseWebSession)
			webProxyGroup.GET("/sessions/:asset_id", webProxy.GetActiveWebSessions)
		}

		// Web proxy routes that don't require auth (heartbeat, cleanup)
		webProxyNoAuth := v1AuthAbandoned.Group("/web_proxy")
		{
			webProxyNoAuth.POST("/heartbeat", webProxy.UpdateWebSessionHeartbeat)
			webProxyNoAuth.POST("/cleanup", webProxy.CleanupWebSession)
		}
	}
}
