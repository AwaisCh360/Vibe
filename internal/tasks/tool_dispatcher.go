package tasks

import (
	"armur-codescanner/internal/logger"
	tools "armur-codescanner/internal/tools"
	utils "armur-codescanner/pkg"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RunSingleToolTask executes a single tool against a cloned repository.
func RunSingleToolTask(toolName, repositoryURL string, options map[string]interface{}) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("repo", repositoryURL).Msgf("panic recovered during single tool scan: %v", r)
		}
	}()

	dirPath, err := utils.CloneRepo(repositoryURL)
	if err != nil {
		logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to clone repository for single tool scan")
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}

	result, err := dispatchTool(toolName, dirPath, options)
	
	// Create a categorized results map matching the format expected by the worker
	categorizedResults := utils.InitCategorizedResults()
	
	if err != nil {
		categorizedResults["scan_errors"] = []interface{}{ScanError{Tool: toolName, Message: err.Error()}}
	} else {
		mergeResultss(categorizedResults, result)
	}

	// Always cleanup the cloned directory
	if err := os.RemoveAll(dirPath); err != nil {
		logger.Warn().Str("dir", dirPath).Err(err).Msg("failed to remove cloned directory")
	}

	// Reformat properly
	newCatResult := utils.ConvertCategorizedResults(categorizedResults)
	return utils.ReformatScanResults(newCatResult)
}

func dispatchTool(toolName, dirPath string, options map[string]interface{}) (map[string]interface{}, error) {
	ctx := context.Background()

	// Switch over 43 tools
	switch toolName {
	// System/Binaries
	case "shellcheck":
		return tools.RunShellCheck(ctx, dirPath, options)
	case "checksec":
		return tools.RunChecksec(ctx, dirPath, options)
	case "cppcheck":
		return tools.RunCppcheck(ctx, dirPath, options)
	case "flawfinder":
		return tools.RunFlawfinder(ctx, dirPath, options)
	case "trivy":
		return tools.RunTrivy(ctx, dirPath, options)
	case "grype":
		return tools.RunGrype(ctx, dirPath, options)
	case "hadolint":
		return tools.RunHadolint(ctx, dirPath, options)
	case "kube-linter":
		return tools.RunKubeLinter(ctx, dirPath, options)
	case "local-php-security-checker":
		return tools.RunComposerAudit(ctx, dirPath, options)
	case "terrascan":
		return tools.RunTerrascan(ctx, dirPath, options)
	case "kics":
		return tools.RunKICS(ctx, dirPath, options)
	case "spotbugs":
		return tools.RunSpotBugs(ctx, dirPath, options)
	case "dependency-check":
		return tools.RunDependencyCheck(ctx, dirPath, options)

	// Golang
	case "govulncheck":
		return tools.RunGovulncheck(ctx, dirPath, options)
	case "staticcheck":
		return tools.RunStaticCheck(ctx, dirPath, options)
	case "gitleaks":
		return tools.RunGitleaks(ctx, dirPath, options)
	case "tfsec":
		return tools.RunTfsec(ctx, dirPath, options)
	case "gosec":
		return tools.RunGosec(ctx, dirPath, options)
	case "golint":
		return tools.RunGolint(ctx, dirPath, options)
	case "govet":
		return tools.RunGovet(ctx, dirPath, options)
	case "gocyclo":
		return tools.RunGocyclo(ctx, dirPath, options)

	// Python & Smart Contracts
	case "pydocstyle":
		return tools.RunPydocstyle(ctx, dirPath, options)
	case "radon":
		return tools.RunRadon(ctx, dirPath, options)
	case "pylint":
		return tools.RunPylint(ctx, dirPath, options)
	case "vulture":
		return tools.RunVulture(ctx, dirPath, options)
	case "pip-audit":
		return tools.RunPipAudit(ctx, dirPath, options)
	case "bandit":
		return tools.RunBandit(ctx, dirPath, options)
	case "trufflehog3":
		return tools.RunTrufflehog(ctx, dirPath, options)
	case "semgrep":
		return tools.RunSemgrep(ctx, dirPath, "--config=auto", options)
	case "slither":
		return tools.RunSlither(ctx, dirPath, options)
	case "myth":
		return tools.RunMythril(ctx, dirPath, options)
	case "checkov":
		return tools.RunCheckov(ctx, dirPath, options)

	// Node/JS
	case "eslint":
		return tools.RunESLintOnRepo(ctx, dirPath, options)
	case "jscpd":
		return tools.RunJSCPD(ctx, dirPath, options)
	case "jsfuzz":
		return tools.RunJSFuzz(ctx, dirPath, 60*time.Second, options)

	// Ruby/PHP
	case "brakeman":
		return tools.RunBrakeman(ctx, dirPath, options)
	case "bundler-audit":
		return tools.RunBundlerAudit(ctx, dirPath, options)
	case "phpcs":
		return tools.RunPHPCS(ctx, dirPath, options)
	case "psalm":
		return tools.RunPsalm(ctx, dirPath, options)

	// Rust
	case "cargo-clippy":
		return tools.RunClippy(ctx, dirPath, options)
	case "cargo-audit":
		return tools.RunCargoAudit(ctx, dirPath, options)
	case "cargo-geiger":
		return tools.RunCargoGeiger(ctx, dirPath, options)

	// Broken / WIP Tools
	case "cdxgen":
		err := tools.RunCdxgen(ctx, dirPath, filepath.Join(dirPath, "bom.json"), options)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"sbom_generated": true}, nil
	case "kube-score":
		return tools.RunKubeScore(ctx, dirPath, options)
	
	default:
		return nil, fmt.Errorf("unsupported single tool: %s", toolName)
	}
}
