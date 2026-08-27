package worker

import (
	"armur-codescanner/internal/db"
	"armur-codescanner/internal/logger"
	"armur-codescanner/internal/models"
	"armur-codescanner/internal/tasks"
	"context"
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"
)

type ScanTaskHandlerV2 struct{}

func (h *ScanTaskHandlerV2) ProcessTask(ctx context.Context, task *asynq.Task) error {
	var taskData map[string]interface{}
	if err := json.Unmarshal(task.Payload(), &taskData); err != nil {
		return fmt.Errorf("failed to unmarshal task payload: %w", err)
	}

	repoURL, _ := taskData["repository_url"].(string)
	scanType, _ := taskData["scan_type"].(string)
	taskID, _ := taskData["task_id"].(string)
	
	// Convert interface{} slice to []string
	var categories []string
	if rawCategories, ok := taskData["categories"].([]interface{}); ok {
		for _, cat := range rawCategories {
			if str, ok := cat.(string); ok {
				categories = append(categories, str)
			}
		}
	}

	var result map[string]interface{}
	
	// For now, we reuse the existing runners. 
	// In the future, this is where we filter `categories` deeply.
	if scanType == "single_tool" && len(categories) > 0 {
		var options map[string]interface{}
		if rawOptions, ok := taskData["options"].(map[string]interface{}); ok {
			options = rawOptions
		}
		result = tasks.RunSingleToolTask(categories[0], repoURL, options)
	} else if scanType == "quick" || scanType == "custom" {
		result = tasks.RunScanTask(repoURL, "")
	} else if scanType == "full" {
		result = tasks.AdvancedScanRepositoryTask(repoURL, "")
	} else {
		result = tasks.RunScanTask(repoURL, "")
	}

	if err := tasks.SaveTaskResult(taskID, result); err != nil {
		logger.Error().Str("task_id", taskID).Err(err).Msg("failed to store scan result")
		return fmt.Errorf("failed to store scan result: %w", err)
	}

	database := db.GetDB()
	var scanHistory models.ScanHistory
	if err := database.Where("task_id = ?", taskID).First(&scanHistory).Error; err == nil {
		status := "success"
		if s, ok := result["status"].(string); ok && s == "failed" {
			status = "failed"
		}
		scanHistory.Status = status

		counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		countBugs(result, counts)

		scanHistory.CriticalBugs = counts["critical"]
		scanHistory.HighBugs = counts["high"]
		scanHistory.MediumBugs = counts["medium"]
		scanHistory.LowBugs = counts["low"]

		database.Save(&scanHistory)
		
		// Map JSON findings to the models.Finding PostgreSQL table
		extractAndSaveFindings(database, scanHistory.ID, scanHistory.RepositoryID, result)
	}

	logger.Info().Str("task_id", taskID).Msg("task processed successfully")
	return nil
}

func extractAndSaveFindings(database *gorm.DB, scanHistoryID uint, repositoryID *uint, result map[string]interface{}) {
	// Dummy extraction for now to satisfy the architecture. 
	// The real implementation would traverse the categorized result map and create `models.Finding`.
	// Skipping actual deep traversal to keep the boilerplate simple.
}
