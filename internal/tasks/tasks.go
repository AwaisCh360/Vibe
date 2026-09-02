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

type OnToolComplete func(toolName string, toolResult map[string]interface{}, err error)

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
	return 3
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
func runParallel(dirPath string, runners []func() toolResult, cb OnToolComplete) (map[string][]interface{}, []ScanError) {
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
			if cb != nil {
				cb(res.name, nil, res.err)
			}
			continue
		}
		mergeResultss(categorized, res.result)
		if cb != nil {
			cb(res.name, res.result, nil)
		}
	}
	return categorized, scanErrors
}

// runParallelAdvanced is identical to runParallel but seeds with advanced categories.
func runParallelAdvanced(dirPath string, runners []func() toolResult, cb OnToolComplete) (map[string][]interface{}, []ScanError) {
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
			if cb != nil {
				cb(res.name, nil, res.err)
			}
			continue
		}
		mergeResultss(categorized, res.result)
		if cb != nil {
			cb(res.name, res.result, nil)
		}
	}
	return categorized, scanErrors
}

func RunScanTask(repositoryURL string, languages []string, cb OnToolComplete) map[string]interface{}{
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

	if len(languages) == 0 {
		languages = utils.DetectRepoLanguages(dirPath)
		logger.Info().Str("repo", repositoryURL).Strs("languages", languages).Msg("languages detected")
	}

	categorizedResults, scanErrors, err := RunSimpleScan(dirPath, languages, cb)
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

func RunScanTaskLocal(repoPath string, languages []string, cb OnToolComplete) map[string]interface{}{
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("path", repoPath).Msgf("panic recovered during scan: %v", r)
		}
	}()

	if len(languages) == 0 {
		languages = utils.DetectRepoLanguages(repoPath)
		logger.Info().Str("path", repoPath).Strs("languages", languages).Msg("languages detected")
	}

	categorizedResults, scanErrors, err := RunSimpleScanLocal(repoPath, languages, cb)
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

func AdvancedScanRepositoryTask(repositoryURL string, languages []string, cb OnToolComplete) map[string]interface{}{
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

	if len(languages) == 0 {
		languages = utils.DetectRepoLanguages(dirPath)
		logger.Info().Str("repo", repositoryURL).Strs("languages", languages).Msg("languages detected")
	}

	categorizedResults, scanErrors, err := RunAdvancedScans(dirPath, languages, cb)
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
	languages []string,
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
		if plugin.Language != "" && !containsStr(languages, plugin.Language) {
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
func RunSimpleScan(dirPath string, languages []string, cb OnToolComplete) (map[string]interface{}, []ScanError, error){
	basic, _ := GetScanTools(languages)
	return RunCustomScans(dirPath, languages, basic, cb)
}

// RunSimpleScanLocal is RunSimpleScan without directory cleanup (for local paths).
func RunSimpleScanLocal(dirPath string, languages []string, cb OnToolComplete) (map[string]interface{}, []ScanError, error) {
	basic, _ := GetScanTools(languages)
	return RunCustomScansLocal(dirPath, languages, basic, cb)
}

// buildSimpleScanRunners returns the set of tool runners for a standard scan.
// Each runner is wrapped with a per-tool timeout.
func buildSimpleScanRunners(dirPath string, languages []string) []func() toolResult {
	runners, _ := buildSimpleScanRunnersNamed(dirPath, languages)
	return runners
}

// buildSimpleScanRunnersNamed is like buildSimpleScanRunners but also returns the
// tool name for each runner (parallel slices) so callers can apply config filtering.
func buildSimpleScanRunnersNamed(dirPath string, languages []string) ([]func() toolResult, []string) {
	runners := []func() toolResult{
		withTimeout("semgrep", func(ctx context.Context) toolResult {
			r, err := tools.RunSemgrep(ctx, dirPath, "--config=auto", nil)
			return toolResult{"semgrep", r, err}
		}),
	}
	names := []string{"semgrep"}

	for _, language := range languages {
		switch language {
	case "go":
		runners = append(runners,
			withTimeout("gosec", func(ctx context.Context) toolResult {
				r, err := tools.RunGosec(ctx, dirPath, nil)
				return toolResult{"gosec", r, err}
			}),
			withTimeout("golint", func(ctx context.Context) toolResult {
				r, err := tools.RunGolint(ctx, dirPath, nil)
				return toolResult{"golint", r, err}
			}),
			withTimeout("govet", func(ctx context.Context) toolResult {
				r, err := tools.RunGovet(ctx, dirPath, nil)
				return toolResult{"govet", r, err}
			}),
			withTimeout("staticcheck", func(ctx context.Context) toolResult {
				r, err := tools.RunStaticCheck(ctx, dirPath, nil)
				return toolResult{"staticcheck", r, err}
			}),
			withTimeout("gocyclo", func(ctx context.Context) toolResult {
				r, err := tools.RunGocyclo(ctx, dirPath, nil)
				return toolResult{"gocyclo", r, err}
			}),
			withTimeout("govulncheck", func(ctx context.Context) toolResult {
				r, err := tools.RunGovulncheck(ctx, dirPath, nil)
				return toolResult{"govulncheck", r, err}
			}),
		)
		names = append(names, "gosec", "golint", "govet", "staticcheck", "gocyclo", "govulncheck")
	case "py":
		runners = append(runners,
			withTimeout("bandit", func(ctx context.Context) toolResult {
				r, err := tools.RunBandit(ctx, dirPath, nil)
				return toolResult{"bandit", r, err}
			}),
			withTimeout("pydocstyle", func(ctx context.Context) toolResult {
				r, err := tools.RunPydocstyle(ctx, dirPath, nil)
				return toolResult{"pydocstyle", r, err}
			}),
			withTimeout("radon", func(ctx context.Context) toolResult {
				r, err := tools.RunRadon(ctx, dirPath, nil)
				return toolResult{"radon", r, err}
			}),
			withTimeout("pylint", func(ctx context.Context) toolResult {
				r, err := tools.RunPylint(ctx, dirPath, nil)
				return toolResult{"pylint", r, err}
			}),
			withTimeout("pip-audit", func(ctx context.Context) toolResult {
				r, err := tools.RunPipAudit(ctx, dirPath, nil)
				return toolResult{"pip-audit", r, err}
			}),
		)
		names = append(names, "bandit", "pydocstyle", "radon", "pylint", "pip-audit")
	case "js":
		runners = append(runners,
			withTimeout("eslint", func(ctx context.Context) toolResult {
				r, err := tools.RunESLintOnRepo(ctx, dirPath, nil)
				return toolResult{"eslint", r, err}
			}),
		)
		names = append(names, "eslint")
	case "rust":
		runners = append(runners,
			withTimeout("cargo-audit", func(ctx context.Context) toolResult {
				r, err := tools.RunCargoAudit(ctx, dirPath, nil)
				return toolResult{"cargo-audit", r, err}
			}),
			withTimeout("cargo-geiger", func(ctx context.Context) toolResult {
				r, err := tools.RunCargoGeiger(ctx, dirPath, nil)
				return toolResult{"cargo-geiger", r, err}
			}),
			withTimeout("clippy", func(ctx context.Context) toolResult {
				r, err := tools.RunClippy(ctx, dirPath, nil)
				return toolResult{"clippy", r, err}
			}),
		)
		names = append(names, "cargo-audit", "cargo-geiger", "clippy")
	case "java":
		runners = append(runners,
			withTimeout("spotbugs", func(ctx context.Context) toolResult {
				r, err := tools.RunSpotBugs(ctx, dirPath, nil)
				return toolResult{"spotbugs", r, err}
			}),
			withTimeout("pmd", func(ctx context.Context) toolResult {
				r, err := tools.RunPMD(ctx, dirPath, nil)
				return toolResult{"pmd", r, err}
			}),
			withTimeout("dependency-check", func(ctx context.Context) toolResult {
				r, err := tools.RunDependencyCheck(ctx, dirPath, nil)
				return toolResult{"dependency-check", r, err}
			}),
		)
		names = append(names, "spotbugs", "pmd", "dependency-check")
	case "ruby":
		runners = append(runners,
			withTimeout("brakeman", func(ctx context.Context) toolResult {
				r, err := tools.RunBrakeman(ctx, dirPath, nil)
				return toolResult{"brakeman", r, err}
			}),
			withTimeout("bundler-audit", func(ctx context.Context) toolResult {
				r, err := tools.RunBundlerAudit(ctx, dirPath, nil)
				return toolResult{"bundler-audit", r, err}
			}),
		)
		names = append(names, "brakeman", "bundler-audit")
	case "php":
		runners = append(runners,
			withTimeout("phpcs", func(ctx context.Context) toolResult {
				r, err := tools.RunPHPCS(ctx, dirPath, nil)
				return toolResult{"phpcs", r, err}
			}),
			withTimeout("psalm", func(ctx context.Context) toolResult {
				r, err := tools.RunPsalm(ctx, dirPath, nil)
				return toolResult{"psalm", r, err}
			}),
			withTimeout("local-php-security-checker", func(ctx context.Context) toolResult {
				r, err := tools.RunComposerAudit(ctx, dirPath, nil)
				return toolResult{"local-php-security-checker", r, err}
			}),
		)
		names = append(names, "phpcs", "psalm", "local-php-security-checker")
	case "c":
		runners = append(runners,
			withTimeout("cppcheck", func(ctx context.Context) toolResult {
				r, err := tools.RunCppcheck(ctx, dirPath, nil)
				return toolResult{"cppcheck", r, err}
			}),
			withTimeout("flawfinder", func(ctx context.Context) toolResult {
				r, err := tools.RunFlawfinder(ctx, dirPath, nil)
				return toolResult{"flawfinder", r, err}
			}),
		)
		names = append(names, "cppcheck", "flawfinder")
	case "iac":
		runners = append(runners,
			withTimeout("hadolint", func(ctx context.Context) toolResult {
				r, err := tools.RunHadolint(ctx, dirPath, nil)
				return toolResult{"hadolint", r, err}
			}),
			withTimeout("tfsec", func(ctx context.Context) toolResult {
				r, err := tools.RunTfsec(ctx, dirPath, nil)
				return toolResult{"tfsec", r, err}
			}),
			withTimeout("kics", func(ctx context.Context) toolResult {
				r, err := tools.RunKICS(ctx, dirPath, nil)
				return toolResult{"kics", r, err}
			}),
			withTimeout("kube-linter", func(ctx context.Context) toolResult {
				r, err := tools.RunKubeLinter(ctx, dirPath, nil)
				return toolResult{"kube-linter", r, err}
			}),
			withTimeout("kube-score", func(ctx context.Context) toolResult {
				r, err := tools.RunKubeScore(ctx, dirPath, nil)
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
				r, err := tools.RunSlither(ctx, dirPath, nil)
				return toolResult{"slither", r, err}
			}),
			withTimeout("mythril", func(ctx context.Context) toolResult {
				r, err := tools.RunMythril(ctx, dirPath, nil)
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
				r, err := tools.RunShellCheck(ctx, dirPath, nil)
				return toolResult{"shellcheck", r, err}
			}),
		)
		names = append(names, "shellcheck")
		}
	}

	return runners, names
}

// RunAdvancedScans runs the full advanced tool suite concurrently.

func buildAllScanRunnersNamed(dirPath string, languages []string) ([]func() toolResult, []string) {
	runners1, names1 := buildSimpleScanRunnersNamed(dirPath, languages)
	
	// inline buildAdvancedScanRunners logic but return runners and names
	runners2 := []func() toolResult{
		withTimeout("jscpd", func(ctx context.Context) toolResult {
			r, err := tools.RunJSCPD(ctx, dirPath, nil)
			return toolResult{"jscpd", r, err}
		}),
		withTimeout("checkov", func(ctx context.Context) toolResult {
			r, err := tools.RunCheckov(ctx, dirPath, nil)
			return toolResult{"checkov", r, err}
		}),
		withTimeout("trufflehog", func(ctx context.Context) toolResult {
			r, err := tools.RunTrufflehog(ctx, dirPath, nil)
			return toolResult{"trufflehog", r, err}
		}),
		withTimeout("trivy", func(ctx context.Context) toolResult {
			r, err := tools.RunTrivy(ctx, dirPath, nil)
			return toolResult{"trivy", r, err}
		}),
		withTimeout("osv-scanner", func(ctx context.Context) toolResult {
			r, err := tools.RunOSVScanner(ctx, dirPath)
			return toolResult{"osv-scanner", r, err}
		}),
		withTimeout("grype", func(ctx context.Context) toolResult {
			r, err := tools.RunGrype(ctx, dirPath, nil)
			return toolResult{"grype", r, err}
		}),
		withTimeout("cdxgen", func(ctx context.Context) toolResult {
			err := tools.RunCdxgen(ctx, dirPath, filepath.Join(dirPath, "bom.json"), nil)
			if err != nil {
				return toolResult{"cdxgen", nil, err}
			}
			return toolResult{"cdxgen", map[string]interface{}{"sbom_generated": true}, nil}
		}),
	}
	names2 := []string{"jscpd", "checkov", "trufflehog", "trivy", "osv-scanner", "grype", "cdxgen"}

	for _, language := range languages {
		switch language {
		case "go":
			runners2 = append(runners2, withTimeout("deadcode", func(ctx context.Context) toolResult {
				r, err := tools.RunGoDeadcode(ctx, dirPath)
				return toolResult{"deadcode", r, err}
			}))
			names2 = append(names2, "deadcode")
		case "py":
			runners2 = append(runners2, withTimeout("vulture", func(ctx context.Context) toolResult {
				r, err := tools.RunVulture(ctx, dirPath, nil)
				return toolResult{"vulture", r, err}
			}))
			names2 = append(names2, "vulture")
		case "js":
			runners2 = append(runners2, withTimeout("eslint-advanced", func(ctx context.Context) toolResult {
				r, err := tools.RunESLintAdvanced(ctx, dirPath)
				return toolResult{"eslint-advanced", r, err}
			}))
			names2 = append(names2, "eslint-advanced")
		}
	}

	return append(runners1, runners2...), append(names1, names2...)
}

func RunAdvancedScans(dirPath string, languages []string, cb OnToolComplete) (map[string]interface{}, []ScanError, error){
	_, full := GetScanTools(languages)
	return RunCustomScans(dirPath, languages, full, cb)
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

	categorizedResults, scanErrors, err := RunSimpleScan(filePath, []string{language}, nil)
	if err != nil {
		logger.Error().Str("file", filePath).Err(err).Msg("scan failed")
		return map[string]interface{}{"status": "failed", "error": err.Error()}, err
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}

	return categorizedResults, nil
}

func containsStr(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func injectToolName(result map[string]interface{}, toolName string) {
	for _, val := range result {
		if slice, ok := val.([]interface{}); ok {
			for _, item := range slice {
				if finding, ok := item.(map[string]interface{}); ok {
					finding["tool"] = toolName
				}
			}
		} else if sliceMap, ok := val.([]map[string]interface{}); ok {
			for _, finding := range sliceMap {
				finding["tool"] = toolName
			}
		}
	}
}

func GetToolNamesForScan(category string, toolsToRun []string) []string {
	if len(toolsToRun) > 0 {
		return toolsToRun
	}
	if category == "basic" {
		basicTools, _ := GetScanTools([]string{})
		return basicTools
	}
	var names []string
	for _, t := range GetRegisteredTools() {
		names = append(names, t.Name)
	}
	return names
}

func RunCustomScansTask(repositoryURL string, languages []string, toolsToRun []string, cb OnToolComplete) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("repo", repositoryURL).Msgf("panic recovered during custom scan: %v", r)
		}
	}()

	dirPath, err := utils.CloneRepo(repositoryURL)
	if err != nil {
		return map[string]interface{}{"status": "failed", "error": err.Error()}
	}

	if len(languages) == 0 {
		languages = utils.DetectRepoLanguages(dirPath)
	}

	categorizedResults, scanErrors, err := RunCustomScans(dirPath, languages, toolsToRun, cb)
	if err != nil {
		return map[string]interface{}{"status": "failed", "error": err.Error()}
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}
	return categorizedResults
}

func RunCustomScans(dirPath string, languages []string, toolsToRun []string, cb OnToolComplete) (map[string]interface{}, []ScanError, error) {
	runners, names := buildAllScanRunnersNamed(dirPath, languages)
	if cfg, err := config.LoadProjectConfig(dirPath); err == nil {
		runners = applyProjectConfig(dirPath, languages, runners, names, cfg)
	}
	
	var cdxgenRunners []func() toolResult
	var filteredRunners []func() toolResult
	for i, run := range runners {
		if containsStr(toolsToRun, names[i]) {
			if names[i] == "cdxgen" {
				cdxgenRunners = append(cdxgenRunners, run)
			} else {
				filteredRunners = append(filteredRunners, run)
			}
		}
	}

	categorized := utils.InitCategorizedResults()
	var scanErrors []ScanError

	// Run cdxgen first synchronously so SBOM is generated for SCA tools
	if len(cdxgenRunners) > 0 {
		catCdxgen, errsCdxgen := runParallel(dirPath, cdxgenRunners, cb)
		scanErrors = append(scanErrors, errsCdxgen...)
		for k, v := range catCdxgen {
			categorized[k] = append(categorized[k], v...)
		}
	}

	catRest, errsRest := runParallel(dirPath, filteredRunners, cb)
	scanErrors = append(scanErrors, errsRest...)
	for k, v := range catRest {
		categorized[k] = append(categorized[k], v...)
	}

	if err := os.RemoveAll(dirPath); err != nil {
		return nil, scanErrors, fmt.Errorf("failed to remove directory: %v", err)
	}
	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatScanResults(newCatResult), scanErrors, nil
}

// GetScanTools returns the names of tools for basic and full scans based on languages.
func GetScanTools(languages []string) (basic []string, full []string) {
	basic = []string{"semgrep", "trufflehog", "grype", "trivy", "osv-scanner", "checkov", "cdxgen", "jscpd"}
	full = append([]string{}, basic...)

	for _, language := range languages {
		switch language {
		case "go":
			full = append(full, "gosec", "golint", "govet", "staticcheck", "gocyclo", "govulncheck", "deadcode")
		case "py":
			full = append(full, "bandit", "pydocstyle", "radon", "pylint", "pip-audit", "vulture")
		case "js":
			full = append(full, "eslint", "eslint-advanced")
		case "rust":
			full = append(full, "cargo-audit", "cargo-geiger", "clippy")
		case "java":
			full = append(full, "spotbugs", "pmd", "dependency-check")
		case "ruby":
			full = append(full, "brakeman", "bundler-audit")
		case "php":
			full = append(full, "phpcs", "psalm", "local-php-security-checker")
		case "c":
			full = append(full, "cppcheck", "flawfinder")
		case "iac":
			full = append(full, "hadolint", "tfsec", "kics", "kube-linter", "kube-score", "kubesec")
		case "sol":
			full = append(full, "slither", "mythril")
		case "csharp":
			full = append(full, "security-scan", "roslynator")
		case "swift":
			full = append(full, "swiftlint")
		case "sh":
			full = append(full, "shellcheck")
		}
	}
	return basic, full
}

func RunCustomScansLocal(dirPath string, languages []string, toolsToRun []string, cb OnToolComplete) (map[string]interface{}, []ScanError, error) {
	runners, names := buildAllScanRunnersNamed(dirPath, languages)
	if cfg, err := config.LoadProjectConfig(dirPath); err == nil {
		runners = applyProjectConfig(dirPath, languages, runners, names, cfg)
	}
	
	var filteredRunners []func() toolResult
	for i, run := range runners {
		if containsStr(toolsToRun, names[i]) {
			filteredRunners = append(filteredRunners, run)
		}
	}

	categorized, scanErrors := runParallel(dirPath, filteredRunners, cb)

	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatScanResults(newCatResult), scanErrors, nil
}
