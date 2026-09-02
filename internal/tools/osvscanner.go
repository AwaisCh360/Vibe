package internal

import (
	"context"

	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

func RunOSVScanner(ctx context.Context, directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "osv-scanner").Str("dir", directory).Msg("running")
	result, err := runOSVScannerOnRepo(ctx, directory, nil)
	if err != nil {
		logger.Warn().Str("tool", "osv-scanner").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitAdvancedCategorizedResults()), err
	}
	ans := categorizeOSVResults(result, directory)
	return utils.ConvertCategorizedResults(ans), nil
}

func runOSVScannerOnRepo(ctx context.Context, directory string, options map[string]interface{}) (string, error) {
	args := []string{"scan", "--format", "json"}
	if _, err := os.Stat(directory + "/bom.json"); err == nil {
		args = append(args, "--sbom", directory+"/bom.json")
	} else {
		args = append(args, "-r", "--call-analysis", "all", directory)
	}
	args = ApplyOptions(args, options)
	cmd := exec.CommandContext(ctx, "osv-scanner", args...)
	output, err := cmd.Output()
	if err != nil {
		// osv-scanner exits non-zero when vulnerabilities are found
		logger.Debug().Str("tool", "osv-scanner").Err(err).Msg("non-zero exit (may still have results)")
	}
	return string(output), nil
}

func categorizeOSVResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	if results == "" {
		return categorizedResults
	}

	var osvResults struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID               string                 `json:"id"`
					Summary          string                 `json:"summary"`
					Severity         interface{}            `json:"severity"`
					DatabaseSpecific map[string]interface{} `json:"database_specific"`
					Affected         []struct {
						Ranges []struct {
							Events []map[string]string `json:"events"`
						} `json:"ranges"`
					} `json:"affected"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}

	err := json.Unmarshal([]byte(results), &osvResults)
	if err != nil {
		logger.Error().Str("tool", "osv-scanner").Err(err).Msg("failed to parse output")
		return categorizedResults
	}

	for _, result := range osvResults.Results {
		for _, packageData := range result.Packages {
			for _, vulnerability := range packageData.Vulnerabilities {
				var fixedVersion string
				for _, affected := range vulnerability.Affected {
					for _, r := range affected.Ranges {
						for _, ev := range r.Events {
							if fixed, ok := ev["fixed"]; ok {
								fixedVersion = fixed
							}
						}
					}
				}

				categorizedVuln := map[string]interface{}{
					"path":              strings.Replace(result.Source.Path, directory, "", 1),
					"package":           packageData.Package.Name,
					"installed_version": packageData.Package.Version,
					"check_id":          vulnerability.ID,
					"message":           vulnerability.Summary,
				}
				if fixedVersion != "" {
					categorizedVuln["fixed_version"] = fixedVersion
				}

				// Try to get severity from database_specific first
				var resolvedSeverity string
				if sev, ok := vulnerability.DatabaseSpecific["severity"].(string); ok && sev != "" {
					resolvedSeverity = sev
				}

				if resolvedSeverity == "" {
					switch severity := vulnerability.Severity.(type) {
					case string:
						resolvedSeverity = severity
					case []interface{}:
						for _, v := range severity {
							if m, ok := v.(map[string]interface{}); ok {
								if score, ok := m["score"].(string); ok {
									resolvedSeverity = score
									break
								}
							} else if s, ok := v.(string); ok {
								resolvedSeverity = s
								break
							}
						}
					}
				}

				if resolvedSeverity != "" {
					categorizedVuln["severity"] = resolvedSeverity
				} else {
					categorizedVuln["severity"] = "Unknown"
				}

				categorizedResults[utils.SCA] = append(categorizedResults[utils.SCA], categorizedVuln)
			}
		}
	}

	if len(categorizedResults[utils.SCA]) == 0 {
		categorizedResults[utils.SCA] = []interface{}{}
	}

	return categorizedResults
}
