package scanning

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"redmantis/internal/assets"
)

// NucleiResult представляет результат сканирования Nuclei
type NucleiResult struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
}

// NucleiScanner представляет сканер Nuclei
type NucleiScanner struct {
	templatesPath string
	rateLimit     int
	concurrency   int
	timeout       time.Duration
	severity      []string
}

// NewNucleiScanner создает новый экземпляр NucleiScanner
func NewNucleiScanner() *NucleiScanner {
	return &NucleiScanner{
		rateLimit:   10,
		concurrency: 25,
		timeout:     30 * time.Second,
		severity:    []string{"critical", "high", "medium"},
	}
}

// SetSeverity устанавливает уровни серьезности для сканирования
func (ns *NucleiScanner) SetSeverity(severity []string) {
	ns.severity = severity
}

// SetRateLimit устанавливает лимит запросов в секунду
func (ns *NucleiScanner) SetRateLimit(limit int) {
	ns.rateLimit = limit
}

// SetConcurrency устанавливает количество одновременных запросов
func (ns *NucleiScanner) SetConcurrency(concurrency int) {
	ns.concurrency = concurrency
}

// SetTimeout устанавливает таймаут для сканирования
func (ns *NucleiScanner) SetTimeout(timeout time.Duration) {
	ns.timeout = timeout
}

// ScanAssets сканирует веб-сервисы из списка активов
func (ns *NucleiScanner) ScanAssets(assetList []assets.Asset) ([]NucleiResult, error) {
	// Извлечь веб-сервисы из активов
	targets := ns.extractWebTargets(assetList)

	if len(targets) == 0 {
		return nil, fmt.Errorf("no web services found in assets")
	}

	// Создать временный файл с целями
	targetsFile, err := ns.createTargetsFile(targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create targets file: %w", err)
	}
	defer os.Remove(targetsFile)

	// Запустить Nuclei
	results, err := ns.runNuclei(targetsFile)
	if err != nil {
		return nil, fmt.Errorf("nuclei scan failed: %w", err)
	}

	return results, nil
}

// extractWebTargets извлекает веб-сервисы из списка активов
func (ns *NucleiScanner) extractWebTargets(assetList []assets.Asset) []string {
	var targets []string
	seen := make(map[string]bool)

	webPorts := map[int]bool{
		80:   true,
		443:  true,
		8080: true,
		8443: true,
		8000: true,
		8888: true,
		9000: true,
	}

	for _, asset := range assetList {
		if asset.Ports == nil || len(asset.Ports) == 0 {
			continue
		}

		for _, port := range asset.Ports {
			if !webPorts[port.Number] {
				continue
			}

			var url string
			if port.Number == 443 || port.Number == 8443 {
				url = fmt.Sprintf("https://%s:%d", asset.Address, port.Number)
			} else {
				url = fmt.Sprintf("http://%s:%d", asset.Address, port.Number)
			}

			// Избежать дубликатов
			if !seen[url] {
				targets = append(targets, url)
				seen[url] = true
			}
		}
	}

	return targets
}

// createTargetsFile создает временный файл со списком целей
func (ns *NucleiScanner) createTargetsFile(targets []string) (string, error) {
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei_targets_%d.txt", time.Now().UnixNano()))

	file, err := os.Create(tmpFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	for _, target := range targets {
		if _, err := file.WriteString(target + "\n"); err != nil {
			return "", err
		}
	}

	return tmpFile, nil
}

// runNuclei запускает Nuclei и возвращает результаты
func (ns *NucleiScanner) runNuclei(targetsFile string) ([]NucleiResult, error) {
	// Проверить наличие Nuclei
	if _, err := exec.LookPath("nuclei"); err != nil {
		return nil, fmt.Errorf("nuclei not found in PATH: %w", err)
	}

	// Создать временный файл для результатов
	resultsFile := filepath.Join(os.TempDir(), fmt.Sprintf("nuclei_results_%d.json", time.Now().UnixNano()))
	defer os.Remove(resultsFile)

	// Построить команду Nuclei
	args := []string{
		"-list", targetsFile,
		"-jsonl", // Используем -jsonl вместо -json (новая версия Nuclei)
		"-o", resultsFile,
		"-rate-limit", fmt.Sprintf("%d", ns.rateLimit),
		"-c", fmt.Sprintf("%d", ns.concurrency),
		"-timeout", fmt.Sprintf("%d", int(ns.timeout.Seconds())),
	}

	if len(ns.severity) > 0 {
		args = append(args, "-severity", strings.Join(ns.severity, ","))
	}

	// Запустить Nuclei
	cmd := exec.Command("nuclei", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Nuclei может вернуть ошибку, но результаты все равно могут быть доступны
		// Проверим, существует ли файл результатов
		if _, statErr := os.Stat(resultsFile); statErr != nil {
			return nil, fmt.Errorf("nuclei execution failed: %w", err)
		}
	}

	// Прочитать результаты
	results, err := ns.parseResults(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	return results, nil
}

// parseResults парсит JSON результаты Nuclei
func (ns *NucleiScanner) parseResults(resultsFile string) ([]NucleiResult, error) {
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []NucleiResult{}, nil
	}

	var results []NucleiResult
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Пропустить невалидные строки
			continue
		}

		results = append(results, result)
	}

	return results, nil
}

// FormatResults форматирует результаты для вывода
func (ns *NucleiScanner) FormatResults(results []NucleiResult) string {
	if len(results) == 0 {
		return "No vulnerabilities found"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n=== Nuclei Scan Results: %d vulnerabilities found ===\n\n", len(results)))

	// Группировать по серьезности
	bySeverity := make(map[string][]NucleiResult)
	for _, result := range results {
		severity := result.Info.Severity
		if severity == "" {
			severity = "unknown"
		}
		bySeverity[severity] = append(bySeverity[severity], result)
	}

	// Вывести по порядку серьезности
	severityOrder := []string{"critical", "high", "medium", "low", "info", "unknown"}
	for _, sev := range severityOrder {
		if vulns, ok := bySeverity[sev]; ok {
			sb.WriteString(fmt.Sprintf("[%s] %d vulnerabilities:\n", strings.ToUpper(sev), len(vulns)))
			for _, vuln := range vulns {
				sb.WriteString(fmt.Sprintf("  - %s\n", vuln.Info.Name))
				sb.WriteString(fmt.Sprintf("    Target: %s\n", vuln.MatchedAt))
				if len(vuln.Info.Tags) > 0 {
					sb.WriteString(fmt.Sprintf("    Tags: %s\n", strings.Join(vuln.Info.Tags, ", ")))
				}
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}
