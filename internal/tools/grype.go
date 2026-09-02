package internal

import (
	"context"

	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// RunGrype runs Grype vulnerability scanner on a container image or directory.
func RunGrype(ctx context.Context, target string, options map[string]interface{}) (map[string]interface{}, error) {
	runTarget := target
	if _, err := os.Stat(target + "/bom.json"); err == nil {
		runTarget = "sbom:" + target + "/bom.json"
	}
	args := ApplyOptions([]string{runTarget, "-o", "json"}, options)
	cmd := exec.CommandContext(ctx, "grype", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// Grype exits 1 when vulns found
		} else {
			return nil, fmt.Errorf("grype error: %w", err)
		}
	}

	return parseGrypeOutput(output)
}

// RunTrivyImage runs Trivy on a container image.
func RunTrivyImage(ctx context.Context, imageRef string) (map[string]interface{}, error) {
	args := ApplyOptions([]string{"image", "--format", "json", imageRef}, nil)
	cmd := exec.CommandContext(ctx, "trivy", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy image error: %w", err)
	}

	return parseTrivyImageOutput(output)
}

func parseGrypeOutput(output []byte) (map[string]interface{}, error) {
	var raw struct {
		Matches []map[string]interface{} `json:"matches"`
	}
	
	if err := json.Unmarshal(output, &raw); err != nil {
		return map[string]interface{}{"sca": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, m := range raw.Matches {
		vuln, _ := m["vulnerability"].(map[string]interface{})
		artifact, _ := m["artifact"].(map[string]interface{})
		
		id, _ := vuln["id"].(string)
		sev, _ := vuln["severity"].(string)
		desc, _ := vuln["description"].(string)
		
		fixVer := ""
		if fix, ok := vuln["fix"].(map[string]interface{}); ok {
			if versions, ok := fix["versions"].([]interface{}); ok && len(versions) > 0 {
				if v, ok := versions[0].(string); ok {
					fixVer = fmt.Sprintf(" → Fix: %s", v)
				}
			}
		}

		if len(desc) > 120 {
			desc = desc[:117] + "..."
		}

		artName, _ := artifact["name"].(string)
		artVer, _ := artifact["version"].(string)

		path := fmt.Sprintf("%s@%s", artName, artVer)
		
		// Extract locations if available
		if locations, ok := artifact["locations"].([]interface{}); ok && len(locations) > 0 {
			if loc, ok := locations[0].(map[string]interface{}); ok {
				if p, ok := loc["path"].(string); ok {
					path = p // Use the actual file path!
				}
			}
		}

		finding := map[string]interface{}{
			"path":     path,
			"package":  artName,
			"installed_version": artVer,
			"line":     0,
			"severity": strings.ToUpper(sev),
			"message":  fmt.Sprintf("%s: %s%s", id, desc, fixVer),
			"cwe":      id,
			"tool":     "grype",
			"vulnerability_id": id,
		}
		
		if fix, ok := vuln["fix"].(map[string]interface{}); ok {
			if versions, ok := fix["versions"].([]interface{}); ok && len(versions) > 0 {
				if v, ok := versions[0].(string); ok {
					finding["fixed_version"] = v
				}
			}
		}
		
		if dataSource, ok := vuln["dataSource"].(string); ok {
			finding["url"] = dataSource
		}
		
		if cvss, ok := vuln["cvss"].([]interface{}); ok && len(cvss) > 0 {
			if cvss0, ok := cvss[0].(map[string]interface{}); ok {
				if metrics, ok := cvss0["metrics"].(map[string]interface{}); ok {
					if baseScore, ok := metrics["baseScore"].(float64); ok {
						finding["likelihood"] = baseScore
					}
				}
			}
		}

		findings = append(findings, finding)
	}

	return map[string]interface{}{"sca": findings}, nil
}

func parseTrivyImageOutput(output []byte) (map[string]interface{}, error) {
	var result struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return map[string]interface{}{"sca": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			fixInfo := ""
			if v.FixedVersion != "" {
				fixInfo = fmt.Sprintf(" → Fix: %s", v.FixedVersion)
			}

			findings = append(findings, map[string]interface{}{
				"path":     fmt.Sprintf("%s (%s@%s)", r.Target, v.PkgName, v.InstalledVersion),
				"line":     0,
				"severity": strings.ToUpper(v.Severity),
				"message":  fmt.Sprintf("%s: %s%s", v.VulnerabilityID, v.Title, fixInfo),
				"cwe":      v.VulnerabilityID,
				"tool":     "trivy-image",
			})
		}
	}

	return map[string]interface{}{"sca": findings}, nil
}
