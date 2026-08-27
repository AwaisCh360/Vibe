package api

import (
	"armur-codescanner/internal/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	// Apply global middleware
	r.Use(middleware.CorrelationID())
	r.Use(middleware.RequestSizeLimit(middleware.MaxUploadSize))

	// Health endpoints (no auth required)
	r.GET("/health", HealthCheck)
	r.GET("/ready", ReadinessCheck)

	// Public Auth routes
	auth := r.Group("/api/v1/auth")
	auth.Use(middleware.RateLimiter(60, 10))
	{
		auth.POST("/signup", Signup)
		auth.POST("/login", Login)
	}

	api := r.Group("/api/v1")
	api.Use(middleware.RateLimiter(60, 10)) // 60 req/min, burst of 10
	api.Use(middleware.JWTMiddleware())
	{
		// User endpoints
		api.GET("/user/about", UserAbout)
		api.PUT("/user/profile", UpdateProfile)
		api.PUT("/user/password", UpdatePassword)

		// Dashboard endpoints
		api.GET("/dashboard/stats", DashboardStats)
		api.GET("/dashboard/history", ScanHistoryList)

		// Scan routes
		api.POST("/scans", CreateScan)
		api.GET("/scans", ListScans)
		api.GET("/scans/:task_id", GetScanStatus)
		api.DELETE("/scans/:task_id", CancelScan)
		api.GET("/scans/:task_id/progress", TaskProgress) // SSE stream

		// Individual Tool Sub-APIs
		toolGroup := api.Group("/scans/tools")
		{
			toolGroup.POST("/:tool_name/scan", CreateDynamicToolScan)
			toolGroup.GET("/:tool_name/status/:task_id", GetToolScanStatus)
			toolGroup.GET("/:tool_name/report/:task_id", GetToolScanReport)
		}

		// Vulnerabilities and Reports
		api.GET("/vulnerabilities", ListVulnerabilities)
		api.PATCH("/vulnerabilities/:id", UpdateVulnerability)
		api.GET("/scans/:task_id/report/owasp", TaskOwasp)
		api.GET("/scans/:task_id/report/sans", TaskSans)
		
		// Repositories
		api.POST("/repositories", CreateRepository)
		api.GET("/repositories", ListRepositories)

	}
}
