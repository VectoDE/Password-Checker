package main

import (
	"bufio"
	"fmt"
	"os"
	"password-checker/src/internal/checker"
	"password-checker/src/internal/api"
	"strconv"
)

func main() {
	// Entry point of the application
	// Displays a menu and processes user input
	for {
		fmt.Println("=== Password Checker ===")
		fmt.Println("1. Test your own password")
		fmt.Println("2. Generate a secure password")
		fmt.Println("3. Exit")
		fmt.Print("Choose an option (1-3): ")

		// Read user input
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		choice := scanner.Text()

		// Handle menu choices
		switch choice {
		case "1":
			testPassword() // Test user-provided password
		case "2":
			generatePassword() // Generate a secure password
		case "3":
			fmt.Println("Goodbye!") // Exit the application
			return
		default:
			fmt.Println("Invalid choice. Please try again.") // Handle invalid input
		}
	}
}

func testPassword() {
	// Function to test the strength and security of a user-provided password
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter your password: ")
	scanner.Scan()
	password := scanner.Text()

	// Check password strength using the checker module
	strength, err := checker.CheckPasswordStrength(password)
	if err != nil {
		fmt.Printf("Password Strength Check Failed: %s\n", err)
	} else {
		fmt.Printf("Password Strength: %s\n", strength)
	}

	// Check if the password has been involved in a data breach
	pwned, err := api.CheckPwned(password)
	if err != nil {
		fmt.Printf("Pwned Check Failed: %s\n", err)
	} else if pwned {
		fmt.Println("Warning: Your password has been found in a data breach!")
	} else {
		fmt.Println("Your password was not found in any data breaches.")
	}
}

func generatePassword() {
	// Function to generate a secure password based on user-specified bit strength
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter the desired bit strength (e.g., 128, 256): ")
	scanner.Scan()
	bitStrengthStr := scanner.Text()

	// Convert the bit strength input to an integer
	bitStrength, err := strconv.Atoi(bitStrengthStr)
	if err != nil || bitStrength <= 0 {
		fmt.Println("Invalid bit strength. Please enter a positive number.")
		return
	}

	// Generate a secure password using the checker module
	password, err := checker.GenerateSecurePassword(bitStrength)
	if err != nil {
		fmt.Printf("Failed to generate password: %s\n", err)
		return
	}

	// Display the generated password
	fmt.Printf("Generated Password: %s\n", password)
}
