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

	// Найти корень проекта для загрузки config.json
	projectRoot := findProjectRoot()
	fmt.Printf("🔍 Project root detected: %s\n", projectRoot)

	configPath := filepath.Join(projectRoot, "config.json")
	fmt.Printf("📄 Config path: %s\n", configPath)

	// Загрузить конфигурацию
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

	// Проверить, включен ли Nuclei
	if !cfg.Nuclei.Enabled {
		fmt.Println("Nuclei scanning is disabled in config.json")
		fmt.Println("To enable, set \"nuclei.enabled\": true in config.json")
		os.Exit(0)
	}

	// Путь к assets.json (в корне проекта)
	assetsFile := filepath.Join(projectRoot, "assets.json")
	if cfg.Files.OutputFile != "" {
		// Если указан относительный путь, сделать его относительно корня проекта
		if !filepath.IsAbs(cfg.Files.OutputFile) {
			assetsFile = filepath.Join(projectRoot, cfg.Files.OutputFile)
		} else {
			assetsFile = cfg.Files.OutputFile
		}
	}

	fmt.Printf("📂 Assets file path: %s\n", assetsFile)

	// Проверить существование файла
	if _, err := os.Stat(assetsFile); os.IsNotExist(err) {
		fmt.Printf("\n❌ Error: File not found: %s\n", assetsFile)
		fmt.Printf("Project root: %s\n", projectRoot)

		// Показать, что было проверено
		fmt.Println("\nChecked paths:")
		fmt.Printf("  - %s\n", assetsFile)
		if cfg.Files.OutputFile != "" {
			fmt.Printf("  - %s (from config)\n", cfg.Files.OutputFile)
		}

		// Показать текущую рабочую директорию
		if wd, err := os.Getwd(); err == nil {
			fmt.Printf("\nCurrent working directory: %s\n", wd)
		}

		// Показать, где находится config.json (если найден)
		if _, err := os.Stat(configPath); err == nil {
			fmt.Printf("Config.json found at: %s\n", configPath)
			fmt.Println("\n💡 Tip: Make sure assets.json is in the same directory as config.json")
		}

		fmt.Println("\nPlease run RedMantis scanner first to generate assets.json:")
		fmt.Println("  sudo ./redmantis")
		os.Exit(1)
	}

	// Загрузить активы
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

	// Создать Nuclei сканер
	fmt.Println("🔧 Initializing Nuclei scanner...")
	nucleiScanner := scanning.NewNucleiScanner()

	// Настроить параметры из конфигурации
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

	// Запустить сканирование
	fmt.Println("🚀 Starting Nuclei vulnerability scan...")
	fmt.Println()
	nucleiResults, err := nucleiScanner.ScanAssets(assetList)
	if err != nil {
		fmt.Printf("❌ Error during Nuclei scan: %v\n", err)
		os.Exit(1)
	}

	// Показать результаты
	if len(nucleiResults) > 0 {
		fmt.Printf("✓ Found %d vulnerabilities\n", len(nucleiResults))
		fmt.Println()
		fmt.Println(nucleiScanner.FormatResults(nucleiResults))
	} else {
		fmt.Println("✓ No vulnerabilities found")
		fmt.Println()
	}

	// Объединить результаты с активами
	fmt.Println("📝 Merging results with assets...")
	nucleiAssets := mergeResults(assetList, nucleiResults)
	fmt.Printf("✓ Merged results for %d assets\n\n", len(nucleiAssets))

	// Сохранить результаты в корне проекта
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

	// Получить абсолютный путь для вывода
	absOutputFile, _ := filepath.Abs(outputFile)
	fmt.Printf("✓ Successfully saved %d assets with Nuclei results to %s\n", len(nucleiAssets), absOutputFile)
	fmt.Println()

	// Статистика
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

	// Статистика по серьезности
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

// findProjectRoot находит корень проекта, ища config.json или go.mod
func findProjectRoot() string {
	// Попробовать получить путь к исполняемому файлу
	execPath, err := os.Executable()
	var startDir string
	if err == nil {
		// Получить директорию исполняемого файла
		execDir := filepath.Dir(execPath)
		// Если это символическая ссылка, получить реальный путь
		if resolved, err := filepath.EvalSymlinks(execDir); err == nil {
			execDir = resolved
		}
		startDir = execDir
	} else {
		// Fallback: использовать текущую рабочую директорию
		wd, err := os.Getwd()
		if err != nil {
			return "." // Последний fallback
		}
		startDir = wd
	}

	// Начать с директории исполняемого файла и подниматься вверх
	dir := startDir
	maxDepth := 10 // Защита от бесконечного цикла
	depth := 0

	for depth < maxDepth {
		// Проверить наличие config.json или go.mod
		configPath := filepath.Join(dir, "config.json")
		goModPath := filepath.Join(dir, "go.mod")

		if _, err := os.Stat(configPath); err == nil {
			return dir
		}
		if _, err := os.Stat(goModPath); err == nil {
			return dir
		}

		// Подняться на уровень выше
		parent := filepath.Dir(dir)
		if parent == dir {
			// Достигли корня файловой системы
			break
		}
		dir = parent
		depth++
	}

	// Если не нашли, попробовать текущую рабочую директорию
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

	// Если все еще не нашли, вернуть текущую рабочую директорию
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// mergeResults объединяет результаты Nuclei с активами
func mergeResults(assetList []assets.Asset, nucleiResults []scanning.NucleiResult) []NucleiAsset {
	// Создать карту результатов по IP адресу
	vulnMap := make(map[string][]scanning.NucleiResult)
	for _, result := range nucleiResults {
		// Попробовать использовать поле IP из результата
		ip := result.IP

		// Если IP пустой, извлечь из MatchedAt
		if ip == "" {
			ip = extractIPFromURL(result.MatchedAt)
		}

		if ip != "" {
			vulnMap[ip] = append(vulnMap[ip], result)
		}
	}

	// Объединить с активами
	nucleiAssets := make([]NucleiAsset, 0, len(assetList))
	for _, asset := range assetList {
		nucleiAsset := NucleiAsset{
			Asset: asset,
		}

		// Добавить уязвимости для этого актива
		if vulns, found := vulnMap[asset.Address]; found {
			nucleiAsset.NucleiVulnerabilities = vulns
		}

		nucleiAssets = append(nucleiAssets, nucleiAsset)
	}

	return nucleiAssets
}

// extractIPFromURL извлекает IP адрес из URL
func extractIPFromURL(urlStr string) string {
	// Попробовать распарсить URL
	parsedURL, err := url.Parse(urlStr)
	if err == nil && parsedURL.Host != "" {
		// Извлечь host (может быть IP:PORT или hostname:PORT)
		host := parsedURL.Host

		// Убрать порт если есть
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}

		return host
	}

	// Fallback: простая обработка формата http://IP:PORT или https://IP:PORT
	if len(urlStr) < 7 {
		return ""
	}

	// Пропустить http:// или https://
	start := 0
	if strings.HasPrefix(urlStr, "http://") {
		start = 7
	} else if strings.HasPrefix(urlStr, "https://") {
		start = 8
	} else {
		return ""
	}

	// Найти IP адрес (до : или /)
	end := start
	for end < len(urlStr) && urlStr[end] != ':' && urlStr[end] != '/' {
		end++
	}

	if end > start {
		return urlStr[start:end]
	}

	return ""
}
