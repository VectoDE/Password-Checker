package app

import (
	"context"
	"errors"

	"github.com/vectode/password-checker/internal/password"
)

// BreachChecker defines an interface capable of checking whether a password has appeared in a breach.
type BreachChecker interface {
	IsBreached(ctx context.Context, password string) (bool, error)
}

// PasswordGenerator represents a secure password generator.
type PasswordGenerator interface {
	Generate(bits int) (string, error)
}

// StrengthEvaluator represents password strength evaluation capabilities.
type StrengthEvaluator interface {
	Evaluate(password string) (password.Strength, []password.Finding)
}

// Service orchestrates password evaluations and password generation.
type Service struct {
	evaluator StrengthEvaluator
	generator PasswordGenerator
	breach    BreachChecker
}

// NewService constructs a service instance.
func NewService(evaluator StrengthEvaluator, generator PasswordGenerator, breach BreachChecker) (*Service, error) {
	if evaluator == nil {
		return nil, errors.New("evaluator cannot be nil")
	}
	if generator == nil {
		return nil, errors.New("generator cannot be nil")
	}
	if breach == nil {
		return nil, errors.New("breach checker cannot be nil")
	}
	return &Service{
		evaluator: evaluator,
		generator: generator,
		breach:    breach,
	}, nil
}

// PasswordAssessment captures the result of evaluating a password.
type PasswordAssessment struct {
	Strength password.Strength
	Findings []password.Finding
	Breached bool
}

// EvaluatePassword checks the strength of the password and whether it has been pwned.
func (s *Service) EvaluatePassword(ctx context.Context, pwd string) (PasswordAssessment, error) {
	strength, findings := s.evaluator.Evaluate(pwd)
	breached, err := s.breach.IsBreached(ctx, pwd)
	if err != nil {
		return PasswordAssessment{}, err
	}

	return PasswordAssessment{
		Strength: strength,
		Findings: findings,
		Breached: breached,
	}, nil
}

// GeneratePassword produces a secure password at the given bit strength.
func (s *Service) GeneratePassword(bits int) (string, error) {
	return s.generator.Generate(bits)
}
