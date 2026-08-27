package api

import (
	"armur-codescanner/internal/db"
	"armur-codescanner/internal/middleware"
	"armur-codescanner/internal/models"
	"armur-codescanner/internal/tasks"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// CreateScan triggers a new scan
func CreateScan(c *gin.Context) {
	var request CreateScanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := middleware.ValidateGitURL(request.RepositoryURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	idFloat, _ := userID.(float64)
	uID := uint(idFloat)

	database := db.GetDB()

	// Find or Create Repository
	var repo models.Repository
	if err := database.Where("user_id = ? AND url = ?", uID, request.RepositoryURL).FirstOrCreate(&repo, models.Repository{
		UserID: uID,
		URL:    request.RepositoryURL,
		Branch: request.Branch,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create repository record"})
		return
	}

	// Enqueue Task (We pass ScanType and Categories to our updated tasks orchestrator)
	taskID, err := tasks.EnqueueScanTaskV2(request.ScanType, request.RepositoryURL, request.Categories)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enqueue scan task", "details": err.Error()})
		return
	}

	// Create ScanHistory
	history := models.ScanHistory{
		UserID:        uID,
		RepositoryID:  &repo.ID,
		TaskID:        taskID,
		RepositoryURL: request.RepositoryURL,
		ScanType:      request.ScanType,
		Categories:    request.Categories,
		Options:       "{}",
		Status:        "pending",
	}
	if err := database.Create(&history).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan history", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ScanSubmitResponse{
		TaskID:   taskID,
		QueuedAt: time.Now(),
	})
}

// CreateDynamicToolScan handles a scan request for a dynamically provided tool name.
func CreateDynamicToolScan(c *gin.Context) {
	toolName := c.Param("tool_name")

	var request CreateScanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := middleware.ValidateGitURL(request.RepositoryURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	idFloat, _ := userID.(float64)
	uID := uint(idFloat)

	database := db.GetDB()

	var repo models.Repository
	if err := database.Where("user_id = ? AND url = ?", uID, request.RepositoryURL).FirstOrCreate(&repo, models.Repository{
		UserID: uID,
		URL:    request.RepositoryURL,
		Branch: request.Branch,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create repository record"})
		return
	}

	taskID, err := tasks.EnqueueSingleToolTask(toolName, request.RepositoryURL, request.Options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enqueue tool scan", "details": err.Error()})
		return
	}

	optionsJSON := "{}"
	if request.Options != nil {
		if b, err := json.Marshal(request.Options); err == nil {
			optionsJSON = string(b)
		}
	}

	history := models.ScanHistory{
		UserID:        uID,
		RepositoryID:  &repo.ID,
		TaskID:        taskID,
		RepositoryURL: request.RepositoryURL,
		ScanType:      "single_tool",
		Categories:    []string{toolName},
		Options:       optionsJSON,
		Status:        "pending",
	}
	if err := database.Create(&history).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save scan history", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ScanSubmitResponse{
		TaskID:   taskID,
		QueuedAt: time.Now(),
	})
}

// GetToolScanStatus returns the status of a specific tool scan.
func GetToolScanStatus(c *gin.Context) {
	toolName := c.Param("tool_name")
	taskID := c.Param("task_id")

	var history models.ScanHistory
	if err := db.GetDB().Where("task_id = ? AND scan_type = 'single_tool' AND categories::jsonb ? ?", taskID, toolName).First(&history).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tool scan not found or tool mismatch"})
		return
	}

	c.JSON(http.StatusOK, history)
}

// GetToolScanReport returns the detailed findings report for a specific tool scan.
func GetToolScanReport(c *gin.Context) {
	toolName := c.Param("tool_name")
	taskID := c.Param("task_id")

	// Same authorization and existence check
	var history models.ScanHistory
	if err := db.GetDB().Where("task_id = ? AND scan_type = 'single_tool' AND categories::jsonb ? ?", taskID, toolName).First(&history).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tool scan not found"})
		return
	}

	var findings []models.Finding
	if err := db.GetDB().Where("scan_history_id = ?", history.ID).Find(&findings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch findings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tool":     toolName,
		"task_id":  taskID,
		"status":   history.Status,
		"findings": findings,
	})
}

// ListScans fetches scans for a user
func ListScans(c *gin.Context) {
	userID, _ := c.Get("user_id")
	idFloat, _ := userID.(float64)

	var scans []models.ScanHistory
	db.GetDB().Where("user_id = ?", uint(idFloat)).Order("created_at desc").Limit(50).Find(&scans)

	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

// GetScanStatus fetches status from DB (or task queue)
func GetScanStatus(c *gin.Context) {
	taskID := c.Param("task_id")
	
	var history models.ScanHistory
	if err := db.GetDB().Where("task_id = ?", taskID).First(&history).Error; err != nil {
		// Fallback to the old TaskStatus implementation if not in DB yet
		TaskStatus(c)
		return
	}

	c.JSON(http.StatusOK, history)
}

// ListVulnerabilities fetches findings across repos
func ListVulnerabilities(c *gin.Context) {
	userID, _ := c.Get("user_id")
	idFloat, _ := userID.(float64)

	var findings []models.Finding
	// We join with ScanHistory to only get findings for this user's scans
	db.GetDB().Joins("JOIN scan_histories ON scan_histories.id = findings.scan_history_id").
		Where("scan_histories.user_id = ?", uint(idFloat)).
		Limit(100).
		Find(&findings)

	c.JSON(http.StatusOK, gin.H{"vulnerabilities": findings})
}

// UpdateVulnerability allows marking findings as false positives
func UpdateVulnerability(c *gin.Context) {
	findingID := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.GetDB().Model(&models.Finding{}).Where("id = ?", findingID).Update("status", req.Status).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update vulnerability"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// CreateRepository registers a new repo
func CreateRepository(c *gin.Context) {
	var req struct {
		URL    string `json:"url" binding:"required"`
		Branch string `json:"branch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := c.Get("user_id")
	idFloat, _ := userID.(float64)

	repo := models.Repository{
		UserID: uint(idFloat),
		URL:    req.URL,
		Branch: req.Branch,
	}
	if err := db.GetDB().Create(&repo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create repo"})
		return
	}

	c.JSON(http.StatusOK, repo)
}

// ListRepositories gets user's repos
func ListRepositories(c *gin.Context) {
	userID, _ := c.Get("user_id")
	idFloat, _ := userID.(float64)

	var repos []models.Repository
	db.GetDB().Where("user_id = ?", uint(idFloat)).Find(&repos)

	c.JSON(http.StatusOK, gin.H{"repositories": repos})
}
