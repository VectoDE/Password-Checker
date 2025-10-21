package password

import (
	"errors"
	"unicode"
)

// Strength represents the qualitative strength of a password.
type Strength string

const (
	// StrengthWeak indicates that the password violates one or more mandatory policy requirements.
	StrengthWeak Strength = "weak"
	// StrengthModerate indicates that the password meets the minimum policy but could be improved.
	StrengthModerate Strength = "moderate"
	// StrengthStrong indicates that the password exceeds the minimum requirements.
	StrengthStrong Strength = "strong"
)

// Severity represents the severity level of a policy finding.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
)

// Finding represents a policy violation or recommendation discovered during evaluation.
type Finding struct {
	Code        string
	Message     string
	Severity    Severity
	Requirement string
}

// Policy describes the password policy enforced by the evaluator.
type Policy struct {
	MinLength int
}

// Evaluator performs password strength checks based on the configured policy.
type Evaluator struct {
	policy Policy
}

// NewEvaluator constructs a new Evaluator instance.
func NewEvaluator(policy Policy) (*Evaluator, error) {
	if policy.MinLength <= 0 {
		return nil, errors.New("minimum length must be greater than zero")
	}
	return &Evaluator{policy: policy}, nil
}

// Evaluate analyses the supplied password and returns its strength alongside policy findings.
func (e *Evaluator) Evaluate(password string) (Strength, []Finding) {
	findings := make([]Finding, 0, 4)

	length := len(password)
	if length < e.policy.MinLength {
		findings = append(findings, Finding{
			Code:        "length.minimum",
			Message:     "password is shorter than the minimum required length",
			Severity:    SeverityError,
			Requirement: "length",
		})
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSymbol(r) || unicode.IsPunct(r):
			hasSpecial = true
		}
	}

	if !hasUpper {
		findings = append(findings, Finding{
			Code:        "charset.uppercase",
			Message:     "add at least one uppercase character",
			Severity:    SeverityWarn,
			Requirement: "character_sets",
		})
	}
	if !hasLower {
		findings = append(findings, Finding{
			Code:        "charset.lowercase",
			Message:     "add at least one lowercase character",
			Severity:    SeverityWarn,
			Requirement: "character_sets",
		})
	}
	if !hasDigit {
		findings = append(findings, Finding{
			Code:        "charset.numeric",
			Message:     "add at least one numeric character",
			Severity:    SeverityWarn,
			Requirement: "character_sets",
		})
	}
	if !hasSpecial {
		findings = append(findings, Finding{
			Code:        "charset.special",
			Message:     "add at least one special character",
			Severity:    SeverityWarn,
			Requirement: "character_sets",
		})
	}

	if IsCommonPassword(password) {
		findings = append(findings, Finding{
			Code:        "password.common",
			Message:     "password is commonly used and easily guessable",
			Severity:    SeverityError,
			Requirement: "common_passwords",
		})
	}

	mandatoryFailures := false
	warnings := 0
	for _, finding := range findings {
		if finding.Severity == SeverityError {
			mandatoryFailures = true
		} else {
			warnings++
		}
	}

	switch {
	case mandatoryFailures:
		return StrengthWeak, findings
	case warnings == 0 && length >= e.policy.MinLength+4 && hasUpper && hasLower && hasDigit && hasSpecial:
		return StrengthStrong, findings
	default:
		return StrengthModerate, findings
	}
}
