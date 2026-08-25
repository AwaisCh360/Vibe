package tasks

import (
	"armur-codescanner/internal/config"
	"armur-codescanner/internal/logger"
	tools "armur-codescanner/internal/tools"
	utils "armur-codescanner/pkg"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ScanError captures a tool-level failure that occurred during a scan.
type ScanError struct {
	Tool    string `json:"tool"`
	Message string `json:"message"`
}

// toolResult holds the output of a single tool execution.
type toolResult struct {
	name   string
	result map[string]interface{}
	err    error
}

// maxConcurrency returns the configured tool concurrency limit.
func maxConcurrency() int {
	if v := os.Getenv("MAX_TOOL_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 5
}

// toolTimeout returns the per-tool execution timeout.
func toolTimeout() time.Duration {
	if v := os.Getenv("TOOL_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 3600 * time.Second
}

// withTimeout wraps a tool runner so that it is cancelled after the configured
// per-tool timeout. If the context expires the runner returns a ScanError.
func withTimeout(name string, run func(ctx context.Context) toolResult) func() toolResult {
	return func() toolResult {
		ctx, cancel := context.WithTimeout(context.Background(), toolTimeout())
		defer cancel()

		ch := make(chan toolResult, 1)
		go func() { ch <- run(ctx) }()

		select {
		case res := <-ch:
			return res
		case <-ctx.Done():
			logger.Warn().Str("tool", name).Dur("timeout", toolTimeout()).Msg("tool timed out")
			return toolResult{name: name, err: fmt.Errorf("tool %s timed out after %v", name, toolTimeout())}
		}
	}
}

// runParallel executes a set of named tool functions concurrently up to the
// configured concurrency limit and returns aggregated results + per-tool errors.
func runParallel(dirPath string, runners []func() toolResult) (map[string][]interface{}, []ScanError) {
	sem := make(chan struct{}, maxConcurrency())
	ch := make(chan toolResult, len(runners))
	var wg sync.WaitGroup

	for _, run := range runners {
		wg.Add(1)
		run := run
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ch <- run()
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	categorized := utils.InitCategorizedResults()
	var scanErrors []ScanError
	for res := range ch {
		if res.err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: res.name, Message: res.err.Error()})
			continue
		}
		mergeResultss(categorized, res.result)
	}
	return categorized, scanErrors
}

// runParallelAdvanced is identical to runParallel but seeds with advanced categories.
func runParallelAdvanced(dirPath string, runners []func() toolResult) (map[string][]interface{}, []ScanError) {
	sem := make(chan struct{}, maxConcurrency())
	ch := make(chan toolResult, len(runners))
	var wg sync.WaitGroup

	for _, run := range runners {
		wg.Add(1)
		run := run
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ch <- run()
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	categorized := utils.InitAdvancedCategorizedResults()
	var scanErrors []ScanError
	for res := range ch {
		if res.err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: res.name, Message: res.err.Error()})
			continue
		}
		mergeResultss(categorized, res.result)
	}
	return categorized, scanErrors
}

func RunScanTask(repositoryURL, language string) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("repo", repositoryURL).Msgf("panic recovered during scan: %v", r)
		}
	}()

	dirPath, err := utils.CloneRepo(repositoryURL)
	if err != nil {
		logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to clone repository")
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}

	if language == "" {
		language = utils.DetectRepoLanguage(dirPath)
		logger.Info().Str("repo", repositoryURL).Str("language", language).Msg("language detected")
	} else {
		if err := utils.RemoveNonRelevantFiles(dirPath, language); err != nil {
			logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to remove non-relevant files")
			return map[string]interface{}{
				"status": "failed",
				"error":  err.Error(),
			}
		}
	}

	categorizedResults, scanErrors, err := RunSimpleScan(dirPath, language)
	if err != nil {
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}
	return categorizedResults
}

func RunScanTaskLocal(repoPath, language string) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("path", repoPath).Msgf("panic recovered during scan: %v", r)
		}
	}()

	if language == "" {
		language = utils.DetectRepoLanguage(repoPath)
		logger.Info().Str("path", repoPath).Str("language", language).Msg("language detected")
	} else {
		if err := utils.RemoveNonRelevantFiles(repoPath, language); err != nil {
			logger.Error().Str("path", repoPath).Err(err).Msg("failed to remove non-relevant files")
			return map[string]interface{}{
				"status": "failed",
				"error":  err.Error(),
			}
		}
	}

	categorizedResults, scanErrors, err := RunSimpleScanLocal(repoPath, language)
	if err != nil {
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}
	return categorizedResults
}

func AdvancedScanRepositoryTask(repositoryURL, language string) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("repo", repositoryURL).Msgf("panic recovered during advanced scan: %v", r)
		}
	}()

	dirPath, err := utils.CloneRepo(repositoryURL)
	if err != nil {
		logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to clone repository")
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}

	if language == "" {
		language = utils.DetectRepoLanguage(dirPath)
		logger.Info().Str("repo", repositoryURL).Str("language", language).Msg("language detected")
	} else {
		if err := utils.RemoveNonRelevantFiles(dirPath, language); err != nil {
			logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to remove non-relevant files")
			return map[string]interface{}{
				"status": "failed",
				"error":  err.Error(),
			}
		}
	}

	categorizedResults, scanErrors, err := RunAdvancedScans(dirPath, language)
	if err != nil {
		logger.Error().Str("repo", repositoryURL).Err(err).Msg("advanced scan failed")
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}
	return categorizedResults
}

// applyProjectConfig filters a set of named runners according to the project
// config's tool allow/block lists, then appends any configured plugins.
func applyProjectConfig(
	dirPath string,
	language string,
	runners []func() toolResult,
	namedRunners []string, // parallel slice of tool names (same order as runners)
	cfg *config.ArmurConfig,
) []func() toolResult {
	if cfg == nil {
		return runners
	}

	// Filter by IsToolEnabled.
	var filtered []func() toolResult
	for i, run := range runners {
		name := ""
		if i < len(namedRunners) {
			name = namedRunners[i]
		}
		if name == "" || cfg.IsToolEnabled(name) {
			filtered = append(filtered, run)
		}
	}

	// Append plugin runners for applicable plugins.
	for _, plugin := range cfg.Plugins {
		plugin := plugin // capture loop var
		if plugin.Language != "" && plugin.Language != language {
			continue
		}
		filtered = append(filtered, withTimeout(plugin.Name, func(ctx context.Context) toolResult {
			result, err := plugin.RunPlugin(dirPath)
			return toolResult{name: plugin.Name, result: result, err: err}
		}))
	}

	return filtered
}

// RunSimpleScan runs the standard tool suite concurrently and returns results.
func RunSimpleScan(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	runners, names := buildSimpleScanRunnersNamed(dirPath, language)
	if cfg, err := config.LoadProjectConfig(dirPath); err == nil {
		runners = applyProjectConfig(dirPath, language, runners, names, cfg)
	}
	categorized, scanErrors := runParallel(dirPath, runners)

	if err := os.RemoveAll(dirPath); err != nil {
		return nil, scanErrors, fmt.Errorf("failed to remove directory: %v", err)
	}
	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatScanResults(newCatResult), scanErrors, nil
}

// RunSimpleScanLocal is RunSimpleScan without directory cleanup (for local paths).
func RunSimpleScanLocal(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	runners, names := buildSimpleScanRunnersNamed(dirPath, language)
	if cfg, err := config.LoadProjectConfig(dirPath); err == nil {
		runners = applyProjectConfig(dirPath, language, runners, names, cfg)
	}
	categorized, scanErrors := runParallel(dirPath, runners)

	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatScanResults(newCatResult), scanErrors, nil
}

// buildSimpleScanRunners returns the set of tool runners for a standard scan.
// Each runner is wrapped with a per-tool timeout.
func buildSimpleScanRunners(dirPath, language string) []func() toolResult {
	runners, _ := buildSimpleScanRunnersNamed(dirPath, language)
	return runners
}

// buildSimpleScanRunnersNamed is like buildSimpleScanRunners but also returns the
// tool name for each runner (parallel slices) so callers can apply config filtering.
func buildSimpleScanRunnersNamed(dirPath, language string) ([]func() toolResult, []string) {
	runners := []func() toolResult{
		withTimeout("semgrep", func(ctx context.Context) toolResult {
			r, err := tools.RunSemgrep(ctx, dirPath, "--config=auto")
			return toolResult{"semgrep", r, err}
		}),
	}
	names := []string{"semgrep"}

	switch language {
	case "go":
		runners = append(runners,
			withTimeout("gosec", func(ctx context.Context) toolResult {
				r, err := tools.RunGosec(ctx, dirPath)
				return toolResult{"gosec", r, err}
			}),
			withTimeout("golint", func(ctx context.Context) toolResult {
				r, err := tools.RunGolint(ctx, dirPath)
				return toolResult{"golint", r, err}
			}),
			withTimeout("govet", func(ctx context.Context) toolResult {
				r, err := tools.RunGovet(ctx, dirPath)
				return toolResult{"govet", r, err}
			}),
			withTimeout("staticcheck", func(ctx context.Context) toolResult {
				r, err := tools.RunStaticCheck(ctx, dirPath)
				return toolResult{"staticcheck", r, err}
			}),
			withTimeout("gocyclo", func(ctx context.Context) toolResult {
				r, err := tools.RunGocyclo(ctx, dirPath)
				return toolResult{"gocyclo", r, err}
			}),
			withTimeout("govulncheck", func(ctx context.Context) toolResult {
				r, err := tools.RunGovulncheck(ctx, dirPath)
				return toolResult{"govulncheck", r, err}
			}),
		)
		names = append(names, "gosec", "golint", "govet", "staticcheck", "gocyclo", "govulncheck")
	case "py":
		runners = append(runners,
			withTimeout("bandit", func(ctx context.Context) toolResult {
				r, err := tools.RunBandit(ctx, dirPath)
				return toolResult{"bandit", r, err}
			}),
			withTimeout("pydocstyle", func(ctx context.Context) toolResult {
				r, err := tools.RunPydocstyle(ctx, dirPath)
				return toolResult{"pydocstyle", r, err}
			}),
			withTimeout("radon", func(ctx context.Context) toolResult {
				r, err := tools.RunRadon(ctx, dirPath)
				return toolResult{"radon", r, err}
			}),
			withTimeout("pylint", func(ctx context.Context) toolResult {
				r, err := tools.RunPylint(ctx, dirPath)
				return toolResult{"pylint", r, err}
			}),
			withTimeout("pip-audit", func(ctx context.Context) toolResult {
				r, err := tools.RunPipAudit(ctx, dirPath)
				return toolResult{"pip-audit", r, err}
			}),
		)
		names = append(names, "bandit", "pydocstyle", "radon", "pylint", "pip-audit")
	case "js":
		runners = append(runners,
			withTimeout("eslint", func(ctx context.Context) toolResult {
				r, err := tools.RunESLintOnRepo(ctx, dirPath)
				return toolResult{"eslint", r, err}
			}),
		)
		names = append(names, "eslint")
	case "rust":
		runners = append(runners,
			withTimeout("cargo-audit", func(ctx context.Context) toolResult {
				r, err := tools.RunCargoAudit(ctx, dirPath)
				return toolResult{"cargo-audit", r, err}
			}),
			withTimeout("cargo-geiger", func(ctx context.Context) toolResult {
				r, err := tools.RunCargoGeiger(ctx, dirPath)
				return toolResult{"cargo-geiger", r, err}
			}),
			withTimeout("clippy", func(ctx context.Context) toolResult {
				r, err := tools.RunClippy(ctx, dirPath)
				return toolResult{"clippy", r, err}
			}),
		)
		names = append(names, "cargo-audit", "cargo-geiger", "clippy")
	case "java":
		runners = append(runners,
			withTimeout("spotbugs", func(ctx context.Context) toolResult {
				r, err := tools.RunSpotBugs(ctx, dirPath)
				return toolResult{"spotbugs", r, err}
			}),
			withTimeout("pmd", func(ctx context.Context) toolResult {
				r, err := tools.RunPMD(ctx, dirPath)
				return toolResult{"pmd", r, err}
			}),
			withTimeout("dependency-check", func(ctx context.Context) toolResult {
				r, err := tools.RunDependencyCheck(ctx, dirPath)
				return toolResult{"dependency-check", r, err}
			}),
		)
		names = append(names, "spotbugs", "pmd", "dependency-check")
	case "ruby":
		runners = append(runners,
			withTimeout("brakeman", func(ctx context.Context) toolResult {
				r, err := tools.RunBrakeman(ctx, dirPath)
				return toolResult{"brakeman", r, err}
			}),
			withTimeout("bundler-audit", func(ctx context.Context) toolResult {
				r, err := tools.RunBundlerAudit(ctx, dirPath)
				return toolResult{"bundler-audit", r, err}
			}),
		)
		names = append(names, "brakeman", "bundler-audit")
	case "php":
		runners = append(runners,
			withTimeout("phpcs", func(ctx context.Context) toolResult {
				r, err := tools.RunPHPCS(ctx, dirPath)
				return toolResult{"phpcs", r, err}
			}),
			withTimeout("psalm", func(ctx context.Context) toolResult {
				r, err := tools.RunPsalm(ctx, dirPath)
				return toolResult{"psalm", r, err}
			}),
			withTimeout("local-php-security-checker", func(ctx context.Context) toolResult {
				r, err := tools.RunComposerAudit(ctx, dirPath)
				return toolResult{"local-php-security-checker", r, err}
			}),
		)
		names = append(names, "phpcs", "psalm", "local-php-security-checker")
	case "c":
		runners = append(runners,
			withTimeout("cppcheck", func(ctx context.Context) toolResult {
				r, err := tools.RunCppcheck(ctx, dirPath)
				return toolResult{"cppcheck", r, err}
			}),
			withTimeout("flawfinder", func(ctx context.Context) toolResult {
				r, err := tools.RunFlawfinder(ctx, dirPath)
				return toolResult{"flawfinder", r, err}
			}),
		)
		names = append(names, "cppcheck", "flawfinder")
	case "iac":
		runners = append(runners,
			withTimeout("hadolint", func(ctx context.Context) toolResult {
				r, err := tools.RunHadolint(ctx, dirPath)
				return toolResult{"hadolint", r, err}
			}),
			withTimeout("tfsec", func(ctx context.Context) toolResult {
				r, err := tools.RunTfsec(ctx, dirPath)
				return toolResult{"tfsec", r, err}
			}),
			withTimeout("kics", func(ctx context.Context) toolResult {
				r, err := tools.RunKICS(ctx, dirPath)
				return toolResult{"kics", r, err}
			}),
			withTimeout("kube-linter", func(ctx context.Context) toolResult {
				r, err := tools.RunKubeLinter(ctx, dirPath)
				return toolResult{"kube-linter", r, err}
			}),
			withTimeout("kube-score", func(ctx context.Context) toolResult {
				r, err := tools.RunKubeScore(ctx, dirPath)
				return toolResult{"kube-score", r, err}
			}),
			withTimeout("kubesec", func(ctx context.Context) toolResult {
				r, err := tools.RunKubesec(ctx, dirPath)
				return toolResult{"kubesec", r, err}
			}),
		)
		names = append(names, "hadolint", "tfsec", "kics", "kube-linter", "kube-score", "kubesec")
	case "sol":
		runners = append(runners,
			withTimeout("slither", func(ctx context.Context) toolResult {
				r, err := tools.RunSlither(ctx, dirPath)
				return toolResult{"slither", r, err}
			}),
			withTimeout("mythril", func(ctx context.Context) toolResult {
				r, err := tools.RunMythril(ctx, dirPath)
				return toolResult{"mythril", r, err}
			}),
		)
		names = append(names, "slither", "mythril")
	case "csharp":
		runners = append(runners,
			withTimeout("security-scan", func(ctx context.Context) toolResult {
				r, err := tools.RunSecurityCodeScan(ctx, dirPath)
				return toolResult{"security-scan", r, err}
			}),
			withTimeout("roslynator", func(ctx context.Context) toolResult {
				r, err := tools.RunRoslynator(ctx, dirPath)
				return toolResult{"roslynator", r, err}
			}),
		)
		names = append(names, "security-scan", "roslynator")
	case "swift":
		runners = append(runners,
			withTimeout("swiftlint", func(ctx context.Context) toolResult {
				r, err := tools.RunSwiftLint(ctx, dirPath)
				return toolResult{"swiftlint", r, err}
			}),
		)
		names = append(names, "swiftlint")
	case "sh":
		runners = append(runners,
			withTimeout("shellcheck", func(ctx context.Context) toolResult {
				r, err := tools.RunShellCheck(ctx, dirPath)
				return toolResult{"shellcheck", r, err}
			}),
		)
		names = append(names, "shellcheck")
	}

	return runners, names
}

// RunAdvancedScans runs the full advanced tool suite concurrently.
func RunAdvancedScans(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	runners := []func() toolResult{
		withTimeout("jscpd", func(ctx context.Context) toolResult {
			r, err := tools.RunJSCPD(ctx, dirPath)
			return toolResult{"jscpd", r, err}
		}),
		withTimeout("checkov", func(ctx context.Context) toolResult {
			r, err := tools.RunCheckov(ctx, dirPath)
			return toolResult{"checkov", r, err}
		}),
		withTimeout("trufflehog", func(ctx context.Context) toolResult {
			r, err := tools.RunTrufflehog(ctx, dirPath)
			return toolResult{"trufflehog", r, err}
		}),
		withTimeout("trivy", func(ctx context.Context) toolResult {
			r, err := tools.RunTrivy(ctx, dirPath)
			return toolResult{"trivy", r, err}
		}),
		withTimeout("osv-scanner", func(ctx context.Context) toolResult {
			r, err := tools.RunOSVScanner(ctx, dirPath)
			return toolResult{"osv-scanner", r, err}
		}),
		withTimeout("grype", func(ctx context.Context) toolResult {
			r, err := tools.RunGrype(ctx, dirPath)
			return toolResult{"grype", r, err}
		}),
		withTimeout("cdxgen", func(ctx context.Context) toolResult {
			err := tools.RunCdxgen(ctx, dirPath, filepath.Join(dirPath, "bom.json"))
			if err != nil {
				return toolResult{"cdxgen", nil, err}
			}
			return toolResult{"cdxgen", map[string]interface{}{"sbom_generated": true}, nil}
		}),
	}

	switch language {
	case "go":
		runners = append(runners, withTimeout("deadcode", func(ctx context.Context) toolResult {
			r, err := tools.RunGoDeadcode(ctx, dirPath)
			return toolResult{"deadcode", r, err}
		}))
	case "py":
		runners = append(runners, withTimeout("vulture", func(ctx context.Context) toolResult {
			r, err := tools.RunVulture(ctx, dirPath)
			return toolResult{"vulture", r, err}
		}))
	case "js":
		runners = append(runners, withTimeout("eslint-advanced", func(ctx context.Context) toolResult {
			r, err := tools.RunESLintAdvanced(ctx, dirPath)
			return toolResult{"eslint-advanced", r, err}
		}))
	}

	categorized, scanErrors := runParallelAdvanced(dirPath, runners)

	if err := os.RemoveAll(dirPath); err != nil {
		return nil, scanErrors, fmt.Errorf("failed to remove directory: %v", err)
	}
	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatAdvancedScanResults(newCatResult), scanErrors, nil
}

func mergeResultss(categorizedResults map[string][]interface{}, newResults map[string]interface{}) {
	for key, newValue := range newResults {
		if newValue == nil {
			if _, exists := categorizedResults[key]; !exists {
				categorizedResults[key] = []interface{}{}
			}
			continue
		}

		newSlice, ok := newValue.([]interface{})
		if !ok {
			continue
		}

		if len(newSlice) == 0 {
			if _, exists := categorizedResults[key]; !exists {
				categorizedResults[key] = []interface{}{}
			}
			continue
		}

		if existingSlice, exists := categorizedResults[key]; exists {
			categorizedResults[key] = append(existingSlice, newSlice...)
		} else {
			categorizedResults[key] = newSlice
		}
	}
}

func ScanFileTask(filePath string) (map[string]interface{}, error) {
	dirPath := filepath.Dir(filePath)

	defer func() {
		if err := os.RemoveAll(dirPath); err != nil {
			logger.Error().Str("dir", dirPath).Err(err).Msg("failed to clean up scan directory")
		} else {
			logger.Debug().Str("dir", dirPath).Msg("cleaned up scan directory")
		}
	}()

	language := utils.DetectFileLanguage(filePath)
	if language == "" {
		err := errors.New("unable to detect file language")
		logger.Error().Str("file", filePath).Err(err).Msg("language detection failed")
		return map[string]interface{}{"status": "failed", "error": err.Error()}, err
	}

	categorizedResults, scanErrors, err := RunSimpleScan(filePath, language)
	if err != nil {
		logger.Error().Str("file", filePath).Err(err).Msg("scan failed")
		return map[string]interface{}{"status": "failed", "error": err.Error()}, err
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}

	return categorizedResults, nil
}
