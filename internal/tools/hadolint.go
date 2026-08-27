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

// RunHadolint runs hadolint on all Dockerfiles found in the given directory.
func RunHadolint(ctx context.Context, directory string, options map[string]interface{}) (map[string]interface{}, error) {
	logger.Info().Str("tool", "hadolint").Str("dir", directory).Msg("running")

	args := ApplyOptions([]string{"--format", "json", directory}, options)
	cmd := exec.CommandContext(ctx, "hadolint", args...)
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
		logger.Debug().Str("tool", "hadolint").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeHadolintResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeHadolintResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var findings []struct {
		File    string `json:"file"`
		Line    int    `json:"line"`
		Code    string `json:"code"`
		Level   string `json:"level"`
		Message string `json:"message"`
		Column  int    `json:"column"`
	}

	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		logger.Error().Str("tool", "hadolint").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	levelToSeverity := map[string]string{
		"error":   "HIGH",
		"warning": "MEDIUM",
		"info":    "LOW",
		"style":   "LOW",
	}

	for _, f := range findings {
		severity := levelToSeverity[f.Level]
		if severity == "" {
			severity = "LOW"
		}
		finding := map[string]interface{}{
			"path":       strings.TrimPrefix(f.File, directory),
			"line":       f.Line,
			"message":    f.Message,
			"severity":   severity,
			"check_id":   f.Code,
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    f.Line,
		}
		categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], finding)
	}

	return categorized
}
