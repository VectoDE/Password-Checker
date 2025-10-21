package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	envHIBPBaseURL        = "HIBP_BASE_URL"
	envHIBPHTTPTimeout    = "HIBP_HTTP_TIMEOUT"
	envHIBPUserAgent      = "HIBP_USER_AGENT"
	envPasswordMinLength  = "PASSWORD_MIN_LENGTH"
	envGeneratorMinLength = "GENERATOR_MIN_LENGTH"
	envGeneratorBits      = "GENERATOR_DEFAULT_BITS"
	envCLImaxRetries      = "CLI_MAX_PROMPT_RETRIES"
	envStoragePath        = "PASSWORD_STORE_PATH"
)

// Config captures all runtime configuration used by the application.
type Config struct {
	Password  PasswordConfig
	Generator GeneratorConfig
	PwnedAPI  PwnedAPIConfig
	CLI       CLIConfig
	Storage   StorageConfig
}

// PasswordConfig defines the runtime password policy.
type PasswordConfig struct {
	MinLength int
}

// GeneratorConfig controls secure password generation.
type GeneratorConfig struct {
	MinLength           int
	DefaultBits         int
	BitsPerCharacter    float64
	AllowedSpecialChars string
}

// PwnedAPIConfig defines settings for the Have I Been Pwned API client.
type PwnedAPIConfig struct {
	BaseURL   string
	Timeout   time.Duration
	UserAgent string
}

// CLIConfig controls behaviour for the interactive CLI.
type CLIConfig struct {
	MaxPromptRetries int
}

// StorageConfig defines persistence options for saved passwords.
type StorageConfig struct {
	Path string
}

const (
	defaultHIBPBaseURL        = "https://api.pwnedpasswords.com/range"
	defaultHTTPTimeout        = 5 * time.Second
	defaultUserAgent          = "password-checker/1.0"
	defaultPasswordMinLength  = 12
	defaultGeneratorMinLength = 16
	defaultGeneratorBits      = 128
	defaultBitsPerCharacter   = 5.95 // ~ log2(len(charset)) for defined charset
	defaultCLIMaxRetries      = 3
	defaultSpecialCharacters  = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
)

// Load reads configuration from environment variables and applies sensible defaults.
func Load() (Config, error) {
	cfg := Config{
		Password: PasswordConfig{
			MinLength: defaultPasswordMinLength,
		},
		Generator: GeneratorConfig{
			MinLength:           defaultGeneratorMinLength,
			DefaultBits:         defaultGeneratorBits,
			BitsPerCharacter:    defaultBitsPerCharacter,
			AllowedSpecialChars: defaultSpecialCharacters,
		},
		PwnedAPI: PwnedAPIConfig{
			BaseURL:   defaultHIBPBaseURL,
			Timeout:   defaultHTTPTimeout,
			UserAgent: defaultUserAgent,
		},
		CLI: CLIConfig{
			MaxPromptRetries: defaultCLIMaxRetries,
		},
		Storage: StorageConfig{
			Path: defaultStoragePath(),
		},
	}

	if baseURL := strings.TrimSpace(os.Getenv(envHIBPBaseURL)); baseURL != "" {
		cfg.PwnedAPI.BaseURL = strings.TrimRight(baseURL, "/")
	}

	if timeoutRaw := strings.TrimSpace(os.Getenv(envHIBPHTTPTimeout)); timeoutRaw != "" {
		duration, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s value: %w", envHIBPHTTPTimeout, err)
		}
		cfg.PwnedAPI.Timeout = duration
	}

	if userAgent := strings.TrimSpace(os.Getenv(envHIBPUserAgent)); userAgent != "" {
		cfg.PwnedAPI.UserAgent = userAgent
	}

	if minLengthRaw := strings.TrimSpace(os.Getenv(envPasswordMinLength)); minLengthRaw != "" {
		minLength, err := strconv.Atoi(minLengthRaw)
		if err != nil || minLength < 1 {
			return Config{}, fmt.Errorf("invalid %s value: %s", envPasswordMinLength, minLengthRaw)
		}
		cfg.Password.MinLength = minLength
	}

	if generatorMinRaw := strings.TrimSpace(os.Getenv(envGeneratorMinLength)); generatorMinRaw != "" {
		minLength, err := strconv.Atoi(generatorMinRaw)
		if err != nil || minLength < 1 {
			return Config{}, fmt.Errorf("invalid %s value: %s", envGeneratorMinLength, generatorMinRaw)
		}
		cfg.Generator.MinLength = minLength
	}

	if bitsRaw := strings.TrimSpace(os.Getenv(envGeneratorBits)); bitsRaw != "" {
		bits, err := strconv.Atoi(bitsRaw)
		if err != nil || bits < 1 {
			return Config{}, fmt.Errorf("invalid %s value: %s", envGeneratorBits, bitsRaw)
		}
		cfg.Generator.DefaultBits = bits
	}

	if retriesRaw := strings.TrimSpace(os.Getenv(envCLImaxRetries)); retriesRaw != "" {
		retries, err := strconv.Atoi(retriesRaw)
		if err != nil || retries < 1 {
			return Config{}, fmt.Errorf("invalid %s value: %s", envCLImaxRetries, retriesRaw)
		}
		cfg.CLI.MaxPromptRetries = retries
	}

	if storagePath := strings.TrimSpace(os.Getenv(envStoragePath)); storagePath != "" {
		if filepath.Clean(storagePath) == "." {
			return Config{}, fmt.Errorf("invalid %s value: %s", envStoragePath, storagePath)
		}
		cfg.Storage.Path = storagePath
	}

	return cfg, nil
}

func defaultStoragePath() string {
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".password-checker", "passwords.json")
	}
	return "passwords.json"
}
