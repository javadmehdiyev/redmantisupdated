package assets

import (
	"encoding/json"
	"fmt"
	"os"

	"redmantis/internal/config"
)

// ExportToJSON serializes asset inventory to JSON format for external consumption.
// Technique: Marshals asset array to indented JSON and writes to configured output file.
// Implements error handling for file operations and provides export statistics.
// Returns error if JSON marshaling or file writing fails.
func ExportToJSON(assets []Asset, cfg *config.Config) error {
	outputFile := cfg.Files.OutputFile
	if outputFile == "" {
		outputFile = "assets.json" // Default fallback
	}

	fmt.Printf("\n💾 Exporting assets to %s...\n", outputFile)

	jsonData, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal assets to JSON: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", outputFile, err)
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write to %s: %w", outputFile, err)
	}

	fmt.Printf("Successfully exported %d assets to %s\n", len(assets), outputFile)
	fmt.Printf("File size: %d bytes\n", len(jsonData))

	return nil
}

// LoadFromJSON loads assets from JSON file
func LoadFromJSON(filename string) ([]Asset, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	var assets []Asset
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return assets, nil
}

// LoadNucleiFromJSON loads nuclei assets from JSON file
func LoadNucleiFromJSON(filename string) ([]NucleiAsset, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	var nucleiAssets []NucleiAsset
	if err := json.Unmarshal(data, &nucleiAssets); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nucleiAssets, nil
}
