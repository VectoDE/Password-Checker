# Password Checker

## Overview

The **Password Checker** is a Go-based command-line application that helps users evaluate the strength and security of their passwords. It checks if a given password is strong enough by analyzing its length, character diversity, and overall complexity. Additionally, it verifies if the password has been exposed in any known data breaches through integration with the **Have I Been Pwned** API.

This tool is aimed at improving password security by guiding users toward better password practices and helping them ensure that their passwords are not compromised.

## Features

- **Password Strength Check**: Evaluates the strength of the password based on length, complexity, and diversity of characters (upper/lowercase letters, numbers, and special characters).
- **Data Breach Check**: Uses the Have I Been Pwned API to check if the password has been exposed in any known data breaches.
- **Secure Password Generator**: Generates strong and random passwords with customizable bit strength, ensuring enhanced security.
- **Common Password Detection**: Identifies if the password is among a list of commonly used and weak passwords.

## Installation

### Requirements

- Go version 1.19 or higher
- A GitHub account (for pulling this repository)

### Steps to Install

1. **Clone the Repository**: Open your terminal and run the following command to clone the repository:

```bash
git clone https://github.com/VectoDE/Password-Checker.git
```

2. **Navigate to the Project Directory**: Change to the project directory:

```bash
cd password-checker
```

3. **Install Dependencies**: Run the following command to install all required dependencies using ```go mod```:

```bash
go mod tidy
```

## Usage

### Running the Application

To run the Password Checker, simply execute the following command in the project directory:

```bash
go run main.go
```

This will start the interactive command-line interface (CLI), where you can:

1. **Test your own password**: Evaluate the strength of an existing password and check if it has been compromised in a data breach.
2. **Generate a secure password**: Generate a new, random password based on a specified bit strength (e.g., 128, 256).
3. **Exit**: Close the application.

## Example Interaction

```bash
=== Password Checker ===
1. Test your own password
2. Generate a secure password
3. Exit
Choose an option (1-3): 1
Enter your password: password123
Password Strength: Moderate
Your password was not found in any data breaches.
```

### Command-Line Interface (CLI) Usage

Alternatively, you can use the CLI directly by passing a password as an argument:

```bash
go run cmd/cli/cli.go -password="your_password"
```

This will check the strength and breach status of the provided password.

## GitHub Actions Integration

This repository includes GitHub Actions workflows for automated code quality checks and tests. The workflow ensures that the code is linted and all tests are passed before merging any changes.

### How It Works:

- **Linting**: The code is analyzed for style issues and potential errors.
- **Testing**: All unit tests are executed to ensure the integrity of the code.

The workflow is triggered on ```push``` and ```pull_request``` events targeting the main branch.

## Folder Structure

Here is an overview of the project's folder structure:

```bash
password-checker/
├── .github/
│   ├── workflows/
│   │   └── go.yml          # GitHub Actions workflow for linting and testing
├── main.go                  # Entry point for the application
├── internal/
│   ├── checker/
│   │   ├── checker.go      # Functions to check password strength and generate passwords
│   │   ├── security.go     # Security-related utilities
│   └── api/
│       └── pwned.go        # Functions to interact with the "Have I Been Pwned" API
├── cmd/
│   └── cli/
│       └── cli.go          # CLI interface for the application
├── config/
│   └── config.go           # Configuration settings
├── tests/
│   ├── checker_test.go     # Unit tests for password checking and security functions
│   ├── api_test.go         # Unit tests for the API interactions
└── go.mod                   # Go module file
```

## Contributing

Contributions to the Password Checker project are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Make your changes and commit them.
4. Push to your forked repository.
5. Open a pull request describing your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/VectoDE/Password-Checker/blob/main/LICENSE) file for details.

## Acknowledgments

- **Have I Been Pwned** for providing the data breach API to help check if passwords have been exposed.
- **Go** for being a fast, reliable, and easy-to-use language for this project.
- **GitHub Actions** for streamlining continuous integration and automated testing.

## Contact

For any questions or issues, feel free to open an issue on the GitHub repository, or contact me via [tim.hauke@hauknetz.de](mailto:tim.hauke@hauknetz.de)
