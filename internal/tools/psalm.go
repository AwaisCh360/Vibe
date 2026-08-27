package internal

import (
	"fmt"
	"context"

	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunPsalm runs the Psalm PHP static analysis tool on a project directory.
func RunPsalm(ctx context.Context, directory string, options map[string]interface{}) (map[string]interface{}, error) {
	logger.Info().Str("tool", "psalm").Str("dir", directory).Msg("running")

	args := ApplyOptions([]string{"--output-format=json",
		"--no-progress",
		directory,}, options)
	cmd := exec.CommandContext(ctx, "psalm", args...)
	cmd.Dir = directory
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("tool execution failed: %w", err)
		}
	}

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "psalm").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizePsalmResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizePsalmResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var issues []struct {
		Type      string `json:"type"`
		Severity  string `json:"severity"`
		FilePath  string `json:"file_path"`
		Line      int    `json:"line_from"`
		EndLine   int    `json:"line_to"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}

	if err := json.Unmarshal([]byte(raw), &issues); err != nil {
		logger.Error().Str("tool", "psalm").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for _, issue := range issues {
		severity := strings.ToUpper(issue.Severity)
		if severity == "" {
			severity = "MEDIUM"
		}
		filePath := strings.TrimPrefix(issue.FilePath, directory)
		finding := map[string]interface{}{
			"path":       filePath,
			"line":       issue.Line,
			"message":    issue.Message,
			"severity":   severity,
			"check_id":   issue.Type,
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    issue.EndLine,
		}
		if issue.Severity == "error" {
			categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
		} else {
			categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], finding)
		}
	}

	return categorized
}
