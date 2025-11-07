package credentials

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"redmantis/internal/assets"

	"golang.org/x/crypto/ssh"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// TestSSH tests SSH credentials
func TestSSH(ip string, port int, creds []Credential, timeout time.Duration) []assets.CredentialTest {
	var results []assets.CredentialTest

	for _, cred := range creds {
		config := &ssh.ClientConfig{
			User: cred.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(cred.Password),
			},
			Timeout:         timeout,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), config)
		if err == nil {
			client.Close()
			results = append(results, assets.CredentialTest{
				Service:  "ssh",
				Port:     port,
				Username: cred.Username,
				Password: cred.Password,
				Success:  true,
			})
			break // Stop after first success
		}
	}

	return results
}

// TestFTP tests FTP credentials (basic implementation)
func TestFTP(ip string, port int, creds []Credential, timeout time.Duration) []assets.CredentialTest {
	var results []assets.CredentialTest

	for _, cred := range creds {
		// Try to connect with basic FTP handshake
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err != nil {
			continue
		}

		// Read FTP greeting
		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buffer)
		if err != nil || n == 0 {
			conn.Close()
			continue
		}

		// Send USER command
		conn.Write([]byte(fmt.Sprintf("USER %s\r\n", cred.Username)))
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err = conn.Read(buffer)
		if err != nil {
			conn.Close()
			continue
		}

		// Send PASS command
		conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", cred.Password)))
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err = conn.Read(buffer)
		conn.Close()

		if err == nil && n > 0 {
			response := string(buffer[:n])
			// FTP 230 means login successful
			if strings.Contains(response, "230") {
				results = append(results, assets.CredentialTest{
					Service:  "ftp",
					Port:     port,
					Username: cred.Username,
					Password: cred.Password,
					Success:  true,
				})
				break
			}
		}
	}

	return results
}

// TestMySQL tests MySQL credentials
func TestMySQL(ip string, port int, creds []Credential, timeout time.Duration) []assets.CredentialTest {
	var results []assets.CredentialTest

	for _, cred := range creds {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=%s",
			cred.Username, cred.Password, ip, port, timeout.String())

		db, err := sql.Open("mysql", dsn)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			err = db.PingContext(ctx)
			cancel()
			db.Close()

			if err == nil {
				results = append(results, assets.CredentialTest{
					Service:  "mysql",
					Port:     port,
					Username: cred.Username,
					Password: cred.Password,
					Success:  true,
				})
				break
			}
		}
	}

	return results
}

// TestPostgreSQL tests PostgreSQL credentials
func TestPostgreSQL(ip string, port int, creds []Credential, timeout time.Duration) []assets.CredentialTest {
	var results []assets.CredentialTest

	for _, cred := range creds {
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
			ip, port, cred.Username, cred.Password, int(timeout.Seconds()))

		db, err := sql.Open("postgres", dsn)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			err = db.PingContext(ctx)
			cancel()
			db.Close()

			if err == nil {
				results = append(results, assets.CredentialTest{
					Service:  "postgresql",
					Port:     port,
					Username: cred.Username,
					Password: cred.Password,
					Success:  true,
				})
				break
			}
		}
	}

	return results
}

// TestHTTP tests HTTP Basic Authentication
func TestHTTP(ip string, port int, creds []Credential, timeout time.Duration, useHTTPS bool) []assets.CredentialTest {
	var results []assets.CredentialTest

	for _, cred := range creds {
		// Try common paths that might require auth
		paths := []string{"/", "/admin", "/manager", "/login"}

		for _, path := range paths {
			// Simple HTTP request with basic auth (simplified)
			// In a real implementation, you'd use net/http with proper auth
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
			if err != nil {
				continue
			}

			// Send HTTP request with basic auth
			authHeader := fmt.Sprintf("%s:%s", cred.Username, cred.Password)
			request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n",
				path, ip, authHeader)

			conn.Write([]byte(request))
			conn.SetReadDeadline(time.Now().Add(timeout))

			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			conn.Close()

			if err == nil && n > 0 {
				response := string(buffer[:n])
				// 200 OK or 3xx redirect (not 401/403)
				if strings.Contains(response, "HTTP/1.1 200") ||
					strings.Contains(response, "HTTP/1.1 30") {
					results = append(results, assets.CredentialTest{
						Service:  "http",
						Port:     port,
						Username: cred.Username,
						Password: cred.Password,
						Success:  true,
					})
					return results
				}
			}
		}
	}

	return results
}

// TestTelnet tests Telnet login
func TestTelnet(ip string, port int, creds []Credential, timeout time.Duration) []assets.CredentialTest {
	var results []assets.CredentialTest

	for _, cred := range creds {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
		if err != nil {
			continue
		}

		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(timeout))

		// Read initial prompt
		conn.Read(buffer)

		// Send username
		conn.Write([]byte(cred.Username + "\n"))
		time.Sleep(500 * time.Millisecond)

		// Read password prompt
		conn.Read(buffer)

		// Send password
		conn.Write([]byte(cred.Password + "\n"))
		time.Sleep(500 * time.Millisecond)

		// Read response
		n, err := conn.Read(buffer)
		conn.Close()

		if err == nil && n > 0 {
			response := string(buffer[:n])
			// Check for success indicators (shell prompt, etc.)
			if !strings.Contains(response, "Login incorrect") &&
				!strings.Contains(response, "Authentication failed") &&
				!strings.Contains(response, "Access denied") {
				results = append(results, assets.CredentialTest{
					Service:  "telnet",
					Port:     port,
					Username: cred.Username,
					Password: cred.Password,
					Success:  true,
				})
				break
			}
		}
	}

	return results
}

// TestSMB tests SMB/CIFS credentials (simplified - just connection test)
func TestSMB(ip string, port int, creds []Credential, timeout time.Duration) []assets.CredentialTest {
	var results []assets.CredentialTest

	// SMB testing is complex - this is a placeholder
	// In production, you'd use github.com/hirochachacha/go-smb2
	// For now, just return empty results
	_ = ip
	_ = port
	_ = creds
	_ = timeout

	return results
}
