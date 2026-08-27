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

// RunBrakeman runs the Brakeman Rails security scanner on a Ruby project directory.
func RunBrakeman(ctx context.Context, directory string, options map[string]interface{}) (map[string]interface{}, error) {
	logger.Info().Str("tool", "brakeman").Str("dir", directory).Msg("running")

	args := ApplyOptions([]string{"-f", "json", "-q", directory}, options)
	cmd := exec.CommandContext(ctx, "brakeman", args...)
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
		logger.Debug().Str("tool", "brakeman").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeBrakemanResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeBrakemanResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Warnings []struct {
			WarningType string  `json:"warning_type"`
			File        string  `json:"file"`
			Line        int     `json:"line"`
			Message     string  `json:"message"`
			Confidence  string  `json:"confidence"`
			Code        string  `json:"code"`
			CVSS        float64 `json:"cvss_score"`
		} `json:"warnings"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "brakeman").Err(err).Msg("failed to parse output")
		return categorized
	}

	confidenceToSeverity := map[string]string{
		"High":   "HIGH",
		"Medium": "MEDIUM",
		"Weak":   "LOW",
	}

	for _, w := range report.Warnings {
		severity := confidenceToSeverity[w.Confidence]
		if severity == "" {
			severity = "MEDIUM"
		}
		filePath := strings.TrimPrefix(w.File, directory)
		finding := map[string]interface{}{
			"path":       filePath,
			"line":       w.Line,
			"message":    w.Message,
			"severity":   severity,
			"check_id":   w.WarningType,
			"confidence": strings.ToUpper(w.Confidence),
			"likelihood": "MEDIUM",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    w.Line,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
