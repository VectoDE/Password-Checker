package checker

import (
	"strings"
)

// IsCommonPassword checks if the given password is a commonly used weak password.
// It compares the provided password against a predefined list of common passwords.
func IsCommonPassword(password string) bool {
	// List of common passwords considered weak
	commonPasswords := []string{
		"123456", "password", "123456789", "12345678", "qwerty", "abc123",
	}

	// Check if the input password matches any of the common passwords
	for _, p := range commonPasswords {
		if strings.ToLower(password) == p {
			return true // The password is weak and commonly used
		}
	}

	// Password is not in the list of common passwords
	return false
}
