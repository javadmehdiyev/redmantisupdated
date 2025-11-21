package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"redmantis/internal/assets"
	"redmantis/internal/config"
	"redmantis/internal/scanning"
)

type NucleiAsset struct {
	assets.Asset
	NucleiVulnerabilities []scanning.NucleiResult `json:"nuclei_vulnerabilities,omitempty"`
}

func main() {
	fmt.Println("RedMantis Nuclei Scanner")
	fmt.Println("========================")
	fmt.Println()

	// Find project root to load config.json
	projectRoot := findProjectRoot()
	fmt.Printf("🔍 Project root detected: %s\n", projectRoot)

	configPath := filepath.Join(projectRoot, "config.json")
	fmt.Printf("📄 Config path: %s\n", configPath)

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("⚠️  Error loading config: %v\n", err)
		fmt.Println("Using default settings...")
		cfg = &config.Config{}
		cfg.Nuclei.Enabled = true
		cfg.Nuclei.Severity = []string{"critical", "high", "medium"}
		cfg.Nuclei.RateLimit = 10
		cfg.Nuclei.Concurrency = 25
		cfg.Nuclei.Timeout = "30s"
	} else {
		fmt.Printf("✓ Config loaded successfully\n")
	}

	// Check if Nuclei is enabled
	if !cfg.Nuclei.Enabled {
		fmt.Println("Nuclei scanning is disabled in config.json")
		fmt.Println("To enable, set \"nuclei.enabled\": true in config.json")
		os.Exit(0)
	}

	// Path to assets.json (in project root)
	assetsFile := filepath.Join(projectRoot, "assets.json")
	if cfg.Files.OutputFile != "" {
		// If relative path is specified, make it relative to project root
		if !filepath.IsAbs(cfg.Files.OutputFile) {
			assetsFile = filepath.Join(projectRoot, cfg.Files.OutputFile)
		} else {
			assetsFile = cfg.Files.OutputFile
		}
	}

	fmt.Printf("📂 Assets file path: %s\n", assetsFile)

	// Check if file exists
	if _, err := os.Stat(assetsFile); os.IsNotExist(err) {
		fmt.Printf("\n❌ Error: File not found: %s\n", assetsFile)
		fmt.Printf("Project root: %s\n", projectRoot)

		// Show what was checked
		fmt.Println("\nChecked paths:")
		fmt.Printf("  - %s\n", assetsFile)
		if cfg.Files.OutputFile != "" {
			fmt.Printf("  - %s (from config)\n", cfg.Files.OutputFile)
		}

		// Show current working directory
		if wd, err := os.Getwd(); err == nil {
			fmt.Printf("\nCurrent working directory: %s\n", wd)
		}

		// Show where config.json is located (if found)
		if _, err := os.Stat(configPath); err == nil {
			fmt.Printf("Config.json found at: %s\n", configPath)
			fmt.Println("\n💡 Tip: Make sure assets.json is in the same directory as config.json")
		}

		fmt.Println("\nPlease run RedMantis scanner first to generate assets.json:")
		fmt.Println("  sudo ./redmantis")
		os.Exit(1)
	}

	// Load assets
	fmt.Printf("📖 Loading assets from %s...\n", assetsFile)
	assetList, err := assets.LoadFromJSON(assetsFile)
	if err != nil {
		fmt.Printf("❌ Error loading assets: %v\n", err)
		os.Exit(1)
	}

	if len(assetList) == 0 {
		fmt.Println("⚠️  No assets found in assets.json")
		os.Exit(0)
	}

	fmt.Printf("✓ Loaded %d assets\n\n", len(assetList))

	// Create Nuclei scanner
	fmt.Println("🔧 Initializing Nuclei scanner...")
	nucleiScanner := scanning.NewNucleiScanner()

	// Configure parameters from config
	if len(cfg.Nuclei.Severity) > 0 {
		nucleiScanner.SetSeverity(cfg.Nuclei.Severity)
		fmt.Printf("  Severity levels: %v\n", cfg.Nuclei.Severity)
	}
	if cfg.Nuclei.RateLimit > 0 {
		nucleiScanner.SetRateLimit(cfg.Nuclei.RateLimit)
		fmt.Printf("  Rate limit: %d req/s\n", cfg.Nuclei.RateLimit)
	}
	if cfg.Nuclei.Concurrency > 0 {
		nucleiScanner.SetConcurrency(cfg.Nuclei.Concurrency)
		fmt.Printf("  Concurrency: %d\n", cfg.Nuclei.Concurrency)
	}
	if cfg.Nuclei.Timeout != "" {
		nucleiScanner.SetTimeout(cfg.GetNucleiTimeout())
		fmt.Printf("  Timeout: %s\n", cfg.Nuclei.Timeout)
	}
	fmt.Println()

	// Start scanning
	fmt.Println("🚀 Starting Nuclei vulnerability scan...")
	fmt.Println()
	nucleiResults, err := nucleiScanner.ScanAssets(assetList)
	if err != nil {
		fmt.Printf("❌ Error during Nuclei scan: %v\n", err)
		os.Exit(1)
	}

	// Show results
	if len(nucleiResults) > 0 {
		fmt.Printf("✓ Found %d vulnerabilities\n", len(nucleiResults))
		fmt.Println()
		fmt.Println(nucleiScanner.FormatResults(nucleiResults))
	} else {
		fmt.Println("✓ No vulnerabilities found")
		fmt.Println()
	}

	// Merge results with assets
	fmt.Println("📝 Merging results with assets...")
	nucleiAssets := mergeResults(assetList, nucleiResults)
	fmt.Printf("✓ Merged results for %d assets\n\n", len(nucleiAssets))

	// Save results to project root
	outputFile := filepath.Join(projectRoot, "nuclei_assets.json")
	fmt.Printf("💾 Saving results to %s...\n", outputFile)

	jsonData, err := json.MarshalIndent(nucleiAssets, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		fmt.Printf("❌ Error writing file: %v\n", err)
		os.Exit(1)
	}

	// Get absolute path for output
	absOutputFile, _ := filepath.Abs(outputFile)
	fmt.Printf("✓ Successfully saved %d assets with Nuclei results to %s\n", len(nucleiAssets), absOutputFile)
	fmt.Println()

	// Statistics
	fmt.Println("📊 Summary:")
	fmt.Printf("  Total assets: %d\n", len(nucleiAssets))

	assetsWithVulns := 0
	totalVulns := 0
	for _, asset := range nucleiAssets {
		if len(asset.NucleiVulnerabilities) > 0 {
			assetsWithVulns++
			totalVulns += len(asset.NucleiVulnerabilities)
		}
	}

	fmt.Printf("  Assets with vulnerabilities: %d\n", assetsWithVulns)
	fmt.Printf("  Total vulnerabilities found: %d\n", totalVulns)

	// Statistics by severity
	severityCount := make(map[string]int)
	for _, asset := range nucleiAssets {
		for _, vuln := range asset.NucleiVulnerabilities {
			severity := vuln.Info.Severity
			if severity == "" {
				severity = "unknown"
			}
			severityCount[severity]++
		}
	}

	if len(severityCount) > 0 {
		fmt.Println("  Vulnerabilities by severity:")
		for sev, count := range severityCount {
			fmt.Printf("    %s: %d\n", sev, count)
		}
	}

	fmt.Println()
	fmt.Println("✅ Scan completed successfully!")
}

// findProjectRoot finds the project root by looking for config.json or go.mod
func findProjectRoot() string {
	// Try to get executable path
	execPath, err := os.Executable()
	var startDir string
	if err == nil {
		// Get executable directory
		execDir := filepath.Dir(execPath)
		// If it's a symlink, get the real path
		if resolved, err := filepath.EvalSymlinks(execDir); err == nil {
			execDir = resolved
		}
		startDir = execDir
	} else {
		// Fallback: use current working directory
		wd, err := os.Getwd()
		if err != nil {
			return "." // Last fallback
		}
		startDir = wd
	}

	// Start from executable directory and go up
	dir := startDir
	maxDepth := 10 // Protection against infinite loop
	depth := 0

	for depth < maxDepth {
		// Check for config.json or go.mod
		configPath := filepath.Join(dir, "config.json")
		goModPath := filepath.Join(dir, "go.mod")

		if _, err := os.Stat(configPath); err == nil {
			return dir
		}
		if _, err := os.Stat(goModPath); err == nil {
			return dir
		}

		// Go up one level
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
		depth++
	}

	// If not found, try current working directory
	wd, err := os.Getwd()
	if err == nil {
		dir = wd
		for depth := 0; depth < maxDepth; depth++ {
			configPath := filepath.Join(dir, "config.json")
			goModPath := filepath.Join(dir, "go.mod")

			if _, err := os.Stat(configPath); err == nil {
				return dir
			}
			if _, err := os.Stat(goModPath); err == nil {
				return dir
			}

			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// If still not found, return current working directory
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// mergeResults merges Nuclei results with assets
func mergeResults(assetList []assets.Asset, nucleiResults []scanning.NucleiResult) []NucleiAsset {
	// Create map of results by IP address
	vulnMap := make(map[string][]scanning.NucleiResult)
	for _, result := range nucleiResults {
		// Try to use IP field from result
		ip := result.IP

		// If IP is empty, extract from MatchedAt
		if ip == "" {
			ip = extractIPFromURL(result.MatchedAt)
		}

		if ip != "" {
			vulnMap[ip] = append(vulnMap[ip], result)
		}
	}

	// Merge with assets
	nucleiAssets := make([]NucleiAsset, 0, len(assetList))
	for _, asset := range assetList {
		nucleiAsset := NucleiAsset{
			Asset: asset,
		}

		// Add vulnerabilities for this asset
		if vulns, found := vulnMap[asset.Address]; found {
			nucleiAsset.NucleiVulnerabilities = vulns
		}

		nucleiAssets = append(nucleiAssets, nucleiAsset)
	}

	return nucleiAssets
}

// extractIPFromURL extracts IP address from URL
func extractIPFromURL(urlStr string) string {
	// Try to parse URL
	parsedURL, err := url.Parse(urlStr)
	if err == nil && parsedURL.Host != "" {
		// Extract host (can be IP:PORT or hostname:PORT)
		host := parsedURL.Host

		// Remove port if present
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}

		return host
	}

	// Fallback: simple handling of http://IP:PORT or https://IP:PORT format
	if len(urlStr) < 7 {
		return ""
	}

	// Skip http:// or https://
	start := 0
	if strings.HasPrefix(urlStr, "http://") {
		start = 7
	} else if strings.HasPrefix(urlStr, "https://") {
		start = 8
	} else {
		return ""
	}

	// Find IP address (until : or /)
	end := start
	for end < len(urlStr) && urlStr[end] != ':' && urlStr[end] != '/' {
		end++
	}

	if end > start {
		return urlStr[start:end]
	}

	return ""
}
