package api

import (
	"net/http"

	"armur-codescanner/internal/db"
	"armur-codescanner/internal/models"

	"github.com/gin-gonic/gin"
)

// @Summary Dashboard Stats
// @Description Get overall statistics of scans for the logged-in user
// @Tags Dashboard
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/dashboard/stats [get]
func DashboardStats(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	idFloat, _ := userID.(float64)
	database := db.GetDB()

	var totalScans int64
	var pendingScans int64
	var failedScans int64
	var successScans int64

	database.Model(&models.ScanHistory{}).Where("user_id = ?", uint(idFloat)).Count(&totalScans)
	database.Model(&models.ScanHistory{}).Where("user_id = ? AND status = ?", uint(idFloat), "pending").Count(&pendingScans)
	database.Model(&models.ScanHistory{}).Where("user_id = ? AND status = ?", uint(idFloat), "failed").Count(&failedScans)
	database.Model(&models.ScanHistory{}).Where("user_id = ? AND status = ?", uint(idFloat), "success").Count(&successScans)

	type BugAggregates struct {
		TotalCritical int64
		TotalHigh     int64
		TotalMedium   int64
		TotalLow      int64
	}
	var agg BugAggregates
	database.Model(&models.ScanHistory{}).
		Where("user_id = ?", uint(idFloat)).
		Select("sum(critical_bugs) as total_critical, sum(high_bugs) as total_high, sum(medium_bugs) as total_medium, sum(low_bugs) as total_low").
		Scan(&agg)

	c.JSON(http.StatusOK, gin.H{
		"total_scans":    totalScans,
		"pending_scans":  pendingScans,
		"failed_scans":   failedScans,
		"success_scans":  successScans,
		"total_critical": agg.TotalCritical,
		"total_high":     agg.TotalHigh,
		"total_medium":   agg.TotalMedium,
		"total_low":      agg.TotalLow,
	})
}

// @Summary Scan History
// @Description Get a list of past scans run by the logged-in user
// @Tags Dashboard
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} []models.ScanHistory
// @Router /api/v1/dashboard/history [get]
func ScanHistoryList(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	idFloat, _ := userID.(float64)
	database := db.GetDB()

	var history []models.ScanHistory
	database.Where("user_id = ?", uint(idFloat)).Order("created_at desc").Limit(50).Find(&history)

	c.JSON(http.StatusOK, gin.H{"history": history})
}
