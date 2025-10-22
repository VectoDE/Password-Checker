# Password Checker

Password Checker is a production-ready Go CLI that validates password strength, checks the Have I Been Pwned (HIBP) breach database, correlates official offline breach datasets, and generates enterprise-grade passwords. The application is architected for maintainability with clear domain boundaries, structured logging, strong configuration defaults, and comprehensive automated tests.

## Features

- **Deterministic Policy Enforcement** – Centralised password policy validation with detailed findings that highlight improvement areas.
- **Global Leak Coverage** – Aggregates the official HIBP password range API with curated governmental leak datasets to flag compromised credentials worldwide.
- **Secure Password Generator** – Cryptographically secure password generator that guarantees character set coverage and configurable entropy targets.
- **Local Password Vault** – Persist generated or validated passwords locally with simple retrieval commands.
- **Enterprise-Grade CLI** – Structured sub-commands (`check`, `generate`, `interactive`) with JSON or human-readable output options.
- **Configuration & Observability** – Robust environment-based configuration, sensible defaults, and structured logging through Go's `slog` package.
- **Automated Quality Gates** – Unit tests covering critical domains (policy, generator, and API client) ensure confidence in production deployments.

## Getting Started

### Prerequisites

- Go **1.21** or newer.

### Installation

```bash
git clone https://github.com/vectode/password-checker.git
cd password-checker
go mod tidy
```

### Building

```bash
go build ./...
```

### Running

The CLI exposes five sub-commands:

#### 1. Check a password

```bash
# Provide password via flag
./password-checker check --password "Sup3r$ecret!"

# Or pipe from stdin for improved secrecy
printf "Sup3r$ecret!" | ./password-checker check

# Render the assessment as JSON
./password-checker check --password "Sup3r$ecret!" --json
```

#### 2. Generate a password

```bash
# Generate a password with the default 128-bit entropy
./password-checker generate

# Specify a custom entropy target
./password-checker generate --bits 192
```

#### 3. Save a password

```bash
# Store a password under a custom label
./password-checker save --label "mail" --password "Sup3r$ecret!"

# Pipe the password value securely
printf "Sup3r$ecret!" | ./password-checker save --label "mail"
```

#### 4. List stored passwords

```bash
./password-checker list
```

#### 5. Interactive mode

```bash
./password-checker interactive
```

Starting the binary without arguments launches the interactive mode automatically. The interactive mode is available in German and guides users through evaluation, generation, and password vault flows.

## Configuration

All options are configured via environment variables. Defaults are designed for production usage.

| Variable | Default | Description |
|----------|---------|-------------|
| `HIBP_BASE_URL` | `https://api.pwnedpasswords.com/range` | Base URL for the HIBP password range API. |
| `HIBP_HTTP_TIMEOUT` | `5s` | Timeout for outbound HIBP requests. |
| `HIBP_USER_AGENT` | `password-checker/1.0` | User agent sent to HIBP (required by their API). |
| `PASSWORD_MIN_LENGTH` | `12` | Minimum password length enforced during evaluation. |
| `GENERATOR_MIN_LENGTH` | `16` | Minimum length for generated passwords. |
| `GENERATOR_DEFAULT_BITS` | `128` | Default entropy target for password generation. |
| `CLI_MAX_PROMPT_RETRIES` | `3` | Maximum invalid menu attempts in interactive mode. |

## Logging

Structured JSON logs are emitted via Go's `slog` package to `stderr` and can be ingested by observability platforms.

## Testing

Execute the full test suite with:

```bash
go test ./...
```

## Project Layout

```
cmd/password-checker/   # Application entry point
internal/app/           # Domain orchestration service
internal/cli/           # Command-line interface implementation
internal/config/        # Environment-backed configuration loader
internal/password/      # Password policy and generator
internal/pwned/         # HIBP API client
internal/version/       # Application version metadata
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
