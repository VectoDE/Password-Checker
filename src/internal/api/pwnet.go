package api

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// CheckPwned checks if a given password has been exposed in a data breach
// using the "Have I Been Pwned" API.
// It implements the k-anonymity model to securely check passwords without exposing them.
func CheckPwned(password string) (bool, error) {
	// Hash the password using SHA-1
	hasher := sha1.New()
	hasher.Write([]byte(password))
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Split the hash into a prefix (first 5 characters) and suffix (remaining characters)
	prefix := hash[:5]
	suffix := strings.ToUpper(hash[5:])

	// Construct the API URL using the hash prefix
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

	// Send an HTTP GET request to the API
	resp, err := http.Get(url)
	if err != nil {
		return false, err // Return error if the request fails
	}
	defer resp.Body.Close()

	// Check if the response status code is not 200 (OK)
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("failed to fetch pwned data: %s", resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err // Return error if the response body cannot be read
	}

	// Split the response into individual entries
	entries := strings.Split(string(body), "\n")
	for _, entry := range entries {
		// Each entry starts with a hash suffix and is followed by a count
		if strings.HasPrefix(entry, suffix) {
			return true, nil // The password has been found in a breach
		}
	}

	// Password not found in the breach database
	return false, nil
}
