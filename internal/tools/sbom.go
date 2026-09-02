package internal

import (
	"context"

	"encoding/json"
	"fmt"
	"os/exec"
)

// RunCdxgen generates a CycloneDX SBOM using cdxgen.
func RunCdxgen(ctx context.Context, dirPath, outputPath string, options map[string]interface{}) error {
	args := ApplyOptions([]string{"--spec-version", "1.5", "-o", outputPath, dirPath}, options)
	cmd := exec.CommandContext(ctx, "cdxgen", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cdxgen error: %w\n%s", err, string(output))
	}
	return nil
}

// RunTrivySBOM generates a CycloneDX SBOM using Trivy.
func RunTrivySBOM(ctx context.Context, dirPath, outputPath string) error {
	args := ApplyOptions([]string{"fs", "--format", "cyclonedx", "--output", outputPath, dirPath}, nil)
	cmd := exec.CommandContext(ctx, "trivy", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy sbom error: %w\n%s", err, string(output))
	}
	return nil
}

// RunTrivySPDX generates an SPDX SBOM using Trivy.
func RunTrivySPDX(ctx context.Context, dirPath, outputPath string) error {
	args := ApplyOptions([]string{"fs", "--format", "spdx-json", "--output", outputPath, dirPath}, nil)
	cmd := exec.CommandContext(ctx, "trivy", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy spdx error: %w\n%s", err, string(output))
	}
	return nil
}

// SupplyChainCheck runs dependency confusion and typosquatting checks.
func SupplyChainCheck(ctx context.Context, dirPath string) (map[string]interface{}, error) {
	findings := []interface{}{}

	// Check for missing lockfiles
	ecosystems := DetectPackageEcosystem(dirPath)
	lockfileMap := map[string]string{
		"npm":      "package-lock.json",
		"pip":      "requirements.txt",
		"go":       "go.sum",
		"cargo":    "Cargo.lock",
		"maven":    "pom.xml",
		"rubygems": "Gemfile.lock",
		"composer": "composer.lock",
	}

	for _, eco := range ecosystems {
		if lockfile, ok := lockfileMap[eco]; ok {
			if !fileExists(ctx, dirPath, lockfile) {
				findings = append(findings, map[string]interface{}{
					"path":     eco,
					"line":     0,
					"severity": "MEDIUM",
					"message":  fmt.Sprintf("Missing lockfile (%s) — dependencies not pinned for reproducibility", lockfile),
					"tool":     "supply-chain-check",
				})
			}
		}
	}

	return map[string]interface{}{"supply_chain": findings}, nil
}

func fileExists(ctx context.Context, dir, name string) bool {
	_, err := exec.CommandContext(ctx, "test", "-f", dir+"/"+name).Output()
	return err == nil
}

// ParseSBOMDependencies extracts dependencies from a CycloneDX SBOM.
func ParseSBOMDependencies(ctx context.Context, sbomPath string) ([]SBOMComponent, error) {
	args := ApplyOptions([]string{sbomPath}, nil)
	cmd := exec.CommandContext(ctx, "cat", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var sbom struct {
		Components []SBOMComponent `json:"components"`
	}
	if err := json.Unmarshal(output, &sbom); err != nil {
		return nil, err
	}

	return sbom.Components, nil
}

// SBOMComponent represents a component in an SBOM.
type SBOMComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	License string `json:"license,omitempty"`
}
