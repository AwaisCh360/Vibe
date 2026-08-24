package internal

import (
	"context"

	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

func RunPylint(ctx context.Context, directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "pylint").Str("dir", directory).Msg("running")
	pylintOutput := RunPylintOnRepo(ctx, directory)
	categorizedResults := CategorizePylintResults(pylintOutput, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func RunPylintOnRepo(ctx context.Context, directory string) string {
	cmd := exec.CommandContext(ctx, "pylint", "--recursive=y", directory, "-f", "json")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	cmd.Run()

	return out.String()
}

func CategorizePylintResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	if results != "" {
		var parsedResults []map[string]interface{}
		err := json.Unmarshal([]byte(results), &parsedResults)
		if err != nil {
			logger.Error().Str("tool", "pylint").Err(err).Msg("failed to parse results")
			return categorizedResults
		}

		directory = strings.ReplaceAll(directory, "/armur/", "")
		for _, result := range parsedResults {
			if path, ok := result["path"].(string); ok {
				result["path"] = strings.ReplaceAll(path, directory, "")
			}
			categorizedResults[ANTIPATTERNS_BUGS] = append(categorizedResults[ANTIPATTERNS_BUGS], result)
		}
	}

	return categorizedResults
}
