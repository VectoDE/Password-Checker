package checker

import (
	"errors"
	"unicode"
	"crypto/rand"
	"math/big"
)

// Charset used for password generation
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/"

// CheckPasswordStrength evaluates the strength of a given password
// and returns "Weak", "Moderate", or "Strong" along with an error if applicable.
func CheckPasswordStrength(password string) (string, error) {
	// Check minimum length
	if len(password) < 8 {
		return "Weak", errors.New("password must be at least 8 characters long")
	}

	// Initialize flags for password complexity
	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true // Contains an uppercase letter
		case unicode.IsLower(char):
			hasLower = true // Contains a lowercase letter
		case unicode.IsNumber(char):
			hasNumber = true // Contains a numeric digit
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true // Contains a special character
		}
	}

	// Evaluate complexity
	if hasUpper && hasLower && hasNumber && hasSpecial {
		return "Strong", nil
	}
	return "Moderate", nil
}

// GenerateSecurePassword creates a password with a desired bit strength.
// The length of the password is derived from the bit strength.
func GenerateSecurePassword(bits int) (string, error) {
	// Validate input bit strength
	if bits <= 0 {
		return "", errors.New("bit strength must be a positive number")
	}

	// Calculate password length based on bit strength (approx. 6 bits per character)
	length := bits / 6
	if length < 8 {
		length = 8 // Ensure a minimum length of 8 characters
	}

	// Generate a random password of the calculated length
	password := make([]byte, length)
	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", errors.New("failed to generate random password")
		}
		password[i] = charset[index.Int64()]
	}

	return string(password), nil
}
