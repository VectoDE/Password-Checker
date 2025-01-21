package cli

import (
	"flag"
	"fmt"
	"password-checker/src/internal/checker"
	"password-checker/src/internal/api"
)

// RunCLI executes the command-line interface for password checking.
// It parses a password from the command line arguments, checks its strength,
// and checks if it has been exposed in a data breach using the "Have I Been Pwned" API.
func RunCLI() {
	// Define the password flag to be passed through the CLI
	password := flag.String("password", "", "The password to check")

	// Parse the command line arguments
	flag.Parse()

	// If no password is provided, print usage instructions
	if *password == "" {
		fmt.Println("Usage: password-checker -password=<password>")
		return
	}

	// Check the strength of the provided password
	strength, err := checker.CheckPasswordStrength(*password)
	if err != nil {
		// If an error occurs during strength check, display the error
		fmt.Printf("Error: %s\n", err)
	} else {
		// Display the password strength
		fmt.Printf("Password Strength: %s\n", strength)
	}

	// Check if the password has been exposed in a data breach
	pwned, err := api.CheckPwned(*password)
	if err != nil {
		// If an error occurs during the pwned check, display the error
		fmt.Printf("Error checking pwned: %s\n", err)
	} else if pwned {
		// If the password is found in a data breach, notify the user
		fmt.Println("Your password is pwned!")
	} else {
		// If the password is safe, notify the user
		fmt.Println("Your password is safe.")
	}
}
