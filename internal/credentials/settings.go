package credentials

import (
	"encoding/json"
	"fmt"
	"os"
)

// CredentialSettings holds the credential configuration from settings.json
type CredentialSettings struct {
	DefaultUsernames []string
	DefaultPasswords []string
	DefaultCombines  []string
	SSHUsers         []string
	FTPUsers         []string
	RDPUsers         []string
}

// SettingsJSON represents the structure of settings.json
type SettingsJSON struct {
	DefaultCreds struct {
		DefaultUsernamesForServices []string `json:"default_usernames_for_services"`
		DefaultPasswordForServices  []string `json:"default_password_for_services"`
		DefaultCombinesForServices  []string `json:"default_combines_for_services"`
		SSHUsers                    []string `json:"ssh_users"`
		FTPUsers                    []string `json:"ftp_users"`
		RDPUsers                    []string `json:"rdp_users"`
	} `json:"default_creds"`
}

// LoadSettings loads credential settings from settings.json file
func LoadSettings(settingsPath string) (*CredentialSettings, error) {
	// Read settings file
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read settings file %s: %w", settingsPath, err)
	}

	// Parse JSON
	var settingsJSON SettingsJSON
	if err := json.Unmarshal(data, &settingsJSON); err != nil {
		return nil, fmt.Errorf("failed to parse settings JSON: %w", err)
	}

	// Convert to CredentialSettings
	settings := &CredentialSettings{
		DefaultUsernames: settingsJSON.DefaultCreds.DefaultUsernamesForServices,
		DefaultPasswords: settingsJSON.DefaultCreds.DefaultPasswordForServices,
		DefaultCombines:  settingsJSON.DefaultCreds.DefaultCombinesForServices,
		SSHUsers:         settingsJSON.DefaultCreds.SSHUsers,
		FTPUsers:         settingsJSON.DefaultCreds.FTPUsers,
		RDPUsers:         settingsJSON.DefaultCreds.RDPUsers,
	}

	return settings, nil
}
