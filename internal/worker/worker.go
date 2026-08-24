package worker

import (
	"armur-codescanner/internal/db"
	"armur-codescanner/internal/logger"
	"armur-codescanner/internal/models"
	"armur-codescanner/internal/tasks"
	"armur-codescanner/internal/webhook"
	utils "armur-codescanner/pkg"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hibiken/asynq"
)

type ScanTaskHandler struct{}

func (h *ScanTaskHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {

	var taskData map[string]string
	if err := json.Unmarshal(task.Payload(), &taskData); err != nil {
		return fmt.Errorf("failed to unmarshal task payload: %w", err)
	}

	repoURL := taskData["repository_url"]
	language := taskData["language"]
	scanType := taskData["scan_type"]
	taskID := taskData["task_id"]
	webhookURL := taskData["webhook_url"]
	webhookSecret := taskData["webhook_secret"]

	var result map[string]interface{}
	switch scanType {
	case utils.SimpleScan:
		result = tasks.RunScanTask(repoURL, language)
	case utils.AdvancedScan:
		result = tasks.AdvancedScanRepositoryTask(repoURL, language)
	case utils.FileScan:
		result, _ = tasks.ScanFileTask(repoURL)
	case utils.LocalScan:
		result = tasks.RunScanTaskLocal(repoURL, language)
	default:
		return fmt.Errorf("unknown scan type: %s", scanType)
	}

	if err := tasks.SaveTaskResult(taskID, result); err != nil {
		logger.Error().Str("task_id", taskID).Err(err).Msg("failed to store scan result")
		return fmt.Errorf("failed to store scan result: %w", err)
	}

	// Sync result status back to the Dashboard DB
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
	}

	// Fire webhook asynchronously if configured.
	if webhookURL != "" {
		go func() {
			d := webhook.NewDelivery(webhookURL, webhookSecret)
			res := d.Send(taskID, result)
			if res.Err != nil {
				logger.Error().
					Str("task_id", taskID).
					Str("webhook_url", webhookURL).
					Err(res.Err).
					Msg("webhook delivery failed")
			}
		}()
	}

	logger.Info().Str("task_id", taskID).Msg("task processed successfully")
	return nil
}

// countBugs recursively searches for "severity" keys in the scan result and tallies them.
func countBugs(v interface{}, counts map[string]int) {
	switch val := v.(type) {
	case map[string]interface{}:
		if sev, ok := val["severity"].(string); ok {
			switch strings.ToLower(sev) {
			case "critical":
				counts["critical"]++
			case "high":
				counts["high"]++
			case "medium":
				counts["medium"]++
			case "low":
				counts["low"]++
			}
		}
		for _, child := range val {
			countBugs(child, counts)
		}
	case []interface{}:
		for _, child := range val {
			countBugs(child, counts)
		}
	case []map[string]interface{}:
		for _, child := range val {
			countBugs(child, counts)
		}
	}
}
