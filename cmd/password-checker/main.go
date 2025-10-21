package main

import (
	"log/slog"
	"os"

	"github.com/vectode/password-checker/internal/app"
	"github.com/vectode/password-checker/internal/cli"
	"github.com/vectode/password-checker/internal/config"
	"github.com/vectode/password-checker/internal/password"
	"github.com/vectode/password-checker/internal/pwned"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	evaluator, err := password.NewEvaluator(password.Policy{MinLength: cfg.Password.MinLength})
	if err != nil {
		logger.Error("failed to create evaluator", "error", err)
		os.Exit(1)
	}

	generator, err := password.NewGenerator(password.GeneratorPolicy{
		MinLength:        cfg.Generator.MinLength,
		BitsPerCharacter: cfg.Generator.BitsPerCharacter,
		SpecialCharset:   cfg.Generator.AllowedSpecialChars,
	})
	if err != nil {
		logger.Error("failed to create generator", "error", err)
		os.Exit(1)
	}

	breachClient, err := pwned.NewClient(cfg.PwnedAPI.BaseURL, cfg.PwnedAPI.UserAgent, cfg.PwnedAPI.Timeout)
	if err != nil {
		logger.Error("failed to create hibp client", "error", err)
		os.Exit(1)
	}

	service, err := app.NewService(evaluator, generator, breachClient)
	if err != nil {
		logger.Error("failed to create service", "error", err)
		os.Exit(1)
	}

	commandLine, err := cli.New(service, cfg, logger)
	if err != nil {
		logger.Error("failed to create cli", "error", err)
		os.Exit(1)
	}

	if err := commandLine.Run(os.Args[1:]); err != nil {
		logger.Error("command execution failed", "error", err)
		os.Exit(1)
	}
}
