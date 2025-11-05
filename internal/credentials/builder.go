package credentials

import (
	"strings"
)

// Credential represents a username/password combination
type Credential struct {
	Username string
	Password string
}

// BuildCredentialList generates a list of credentials to test for a specific service
func BuildCredentialList(settings *CredentialSettings, service string) []Credential {
	var creds []Credential
	seen := make(map[string]bool) // Avoid duplicates

	addCred := func(username, password string) {
		key := username + ":" + password
		if !seen[key] {
			seen[key] = true
			creds = append(creds, Credential{
				Username: username,
				Password: password,
			})
		}
	}

	// 1. Add explicit combines first (highest priority)
	for _, combine := range settings.DefaultCombines {
		parts := strings.SplitN(combine, ":", 2)
		if len(parts) == 2 {
			addCred(parts[0], parts[1])
		}
	}

	// 2. Add service-specific users with default passwords
	var serviceUsers []string
	switch strings.ToLower(service) {
	case "ssh":
		serviceUsers = settings.SSHUsers
	case "ftp":
		serviceUsers = settings.FTPUsers
	case "rdp":
		serviceUsers = settings.RDPUsers
	default:
		serviceUsers = settings.DefaultUsernames
	}

	// Service-specific users × default passwords
	for _, user := range serviceUsers {
		for _, pass := range settings.DefaultPasswords {
			addCred(user, pass)
		}
		// Also try user:user combinations
		addCred(user, user)
		// Try blank password
		addCred(user, "")
	}

	// 3. Default username × password matrix
	for _, user := range settings.DefaultUsernames {
		for _, pass := range settings.DefaultPasswords {
			addCred(user, pass)
		}
	}

	// 4. Common variations
	commonUsers := []string{"admin", "root", "administrator", "user", "test"}
	commonPasses := []string{"admin", "root", "password", "123456", "test", ""}

	for _, user := range commonUsers {
		for _, pass := range commonPasses {
			addCred(user, pass)
		}
		// user:user pattern
		addCred(user, user)
	}

	return creds
}
