package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vectode/password-checker/internal/app"
	"github.com/vectode/password-checker/internal/config"
	"github.com/vectode/password-checker/internal/password"
	"github.com/vectode/password-checker/internal/version"
)

// CLI hosts the command-line interface logic.
type CLI struct {
	service   *app.Service
	cfg       config.Config
	logger    *slog.Logger
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	stdinFile *os.File
}

// New instantiates the CLI with default IO streams.
func New(service *app.Service, cfg config.Config, logger *slog.Logger) (*CLI, error) {
	if service == nil {
		return nil, errors.New("service cannot be nil")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}
	stdin := os.Stdin
	if stdin == nil {
		return nil, errors.New("stdin must be available")
	}
	return &CLI{
		service:   service,
		cfg:       cfg,
		logger:    logger,
		stdin:     os.Stdin,
		stdout:    os.Stdout,
		stderr:    os.Stderr,
		stdinFile: stdin,
	}, nil
}

// Run executes the CLI using the provided arguments.
func (c *CLI) Run(args []string) error {
	if len(args) == 0 {
		c.printUsage()
		return nil
	}

	switch args[0] {
	case "check":
		return c.runCheck(args[1:])
	case "generate":
		return c.runGenerate(args[1:])
	case "interactive":
		return c.runInteractive(args[1:])
	case "--help", "-h":
		c.printUsage()
		return nil
	case "--version", "-v":
		fmt.Fprintln(c.stdout, version.Version)
		return nil
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func (c *CLI) runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	passwordFlag := fs.String("password", "", "Password to evaluate. If omitted, the password is read from standard input.")
	jsonOutput := fs.Bool("json", false, "Render the output as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	pwd := strings.TrimSpace(*passwordFlag)
	if pwd == "" {
		piped, err := c.readPasswordFromPipe()
		if err != nil {
			return err
		}
		pwd = piped
	}

	if pwd == "" {
		return errors.New("no password provided; use --password or pipe a password to stdin")
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.PwnedAPI.Timeout+2*time.Second)
	defer cancel()

	assessment, err := c.service.EvaluatePassword(ctx, pwd)
	if err != nil {
		return err
	}

	if *jsonOutput {
		return c.printAssessmentJSON(assessment)
	}

	c.printAssessmentHuman(assessment)
	return nil
}

func (c *CLI) runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	bitsFlag := fs.Int("bits", c.cfg.Generator.DefaultBits, "Bit strength for the generated password")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	bits := *bitsFlag
	if bits <= 0 {
		return errors.New("bits must be greater than zero")
	}

	password, err := c.service.GeneratePassword(bits)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, password)
	return nil
}

func (c *CLI) runInteractive(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("interactive command does not accept arguments: %v", args)
	}

	reader := bufio.NewReader(c.stdin)
	for attempts := 0; attempts < c.cfg.CLI.MaxPromptRetries; attempts++ {
		fmt.Fprintln(c.stdout, "=== Password Checker ===")
		fmt.Fprintln(c.stdout, "1. Prüfe ein Passwort")
		fmt.Fprintln(c.stdout, "2. Generiere ein Passwort")
		fmt.Fprintln(c.stdout, "3. Beenden")
		fmt.Fprint(c.stdout, "Auswahl (1-3): ")

		choice, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Fprint(c.stdout, "Passwort eingeben: ")
			pwd, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			pwd = strings.TrimSpace(pwd)

			ctx, cancel := context.WithTimeout(context.Background(), c.cfg.PwnedAPI.Timeout+2*time.Second)
			assessment, err := c.service.EvaluatePassword(ctx, pwd)
			cancel()
			if err != nil {
				return err
			}
			c.printAssessmentHuman(assessment)
		case "2":
			fmt.Fprintf(c.stdout, "Bit-Stärke (Standard %d): ", c.cfg.Generator.DefaultBits)
			input, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			input = strings.TrimSpace(input)
			bits := c.cfg.Generator.DefaultBits
			if input != "" {
				parsed, err := strconv.Atoi(input)
				if err != nil {
					fmt.Fprintf(c.stdout, "Ungültige Eingabe: %v\n", err)
					continue
				}
				if parsed <= 0 {
					fmt.Fprintln(c.stdout, "Ungültige Eingabe: Wert muss positiv sein.")
					continue
				}
				bits = parsed
			}
			password, err := c.service.GeneratePassword(bits)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.stdout, "Generiertes Passwort: %s\n", password)
		case "3":
			fmt.Fprintln(c.stdout, "Auf Wiedersehen!")
			return nil
		default:
			fmt.Fprintln(c.stdout, "Ungültige Auswahl. Bitte erneut versuchen.")
		}
	}
	return errors.New("maximale Anzahl an Versuchen überschritten")
}

func (c *CLI) printUsage() {
	fmt.Fprintf(c.stdout, "Password Checker %s\n", version.Version)
	fmt.Fprintln(c.stdout, "Usage:")
	fmt.Fprintln(c.stdout, "  password-checker <command> [options]")
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "Commands:")
	fmt.Fprintln(c.stdout, "  check        Evaluate a password for strength and breaches")
	fmt.Fprintln(c.stdout, "  generate     Generate a secure password")
	fmt.Fprintln(c.stdout, "  interactive  Launch the interactive mode")
	fmt.Fprintln(c.stdout, "  --version    Print the application version")
	fmt.Fprintln(c.stdout, "  --help       Show this help message")
}

func (c *CLI) printAssessmentJSON(assessment app.PasswordAssessment) error {
	payload := struct {
		Strength string             `json:"strength"`
		Findings []password.Finding `json:"findings"`
		Breached bool               `json:"breached"`
	}{
		Strength: string(assessment.Strength),
		Findings: assessment.Findings,
		Breached: assessment.Breached,
	}

	encoder := json.NewEncoder(c.stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func (c *CLI) printAssessmentHuman(assessment app.PasswordAssessment) {
	fmt.Fprintf(c.stdout, "Stärke: %s\n", strings.ToUpper(string(assessment.Strength)))
	if len(assessment.Findings) == 0 {
		fmt.Fprintln(c.stdout, "Keine Richtlinienverletzungen gefunden.")
	} else {
		fmt.Fprintln(c.stdout, "Hinweise:")
		for _, finding := range assessment.Findings {
			fmt.Fprintf(c.stdout, " - [%s] %s\n", strings.ToUpper(string(finding.Severity)), finding.Message)
		}
	}
	if assessment.Breached {
		fmt.Fprintln(c.stdout, "Warnung: Dieses Passwort wurde in Datenlecks gefunden.")
	} else {
		fmt.Fprintln(c.stdout, "Keine Treffer in bekannten Datenlecks.")
	}
}

func (c *CLI) readPasswordFromPipe() (string, error) {
	info, err := c.stdinFile.Stat()
	if err != nil {
		return "", fmt.Errorf("unable to stat stdin: %w", err)
	}

	if (info.Mode() & os.ModeCharDevice) != 0 {
		return "", nil
	}

	data, err := io.ReadAll(c.stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read from stdin: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}
