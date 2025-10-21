package password

import "testing"

func TestNewEvaluatorValidation(t *testing.T) {
	if _, err := NewEvaluator(Policy{MinLength: 0}); err == nil {
		t.Fatalf("expected error for min length <= 0")
	}
}

func TestEvaluatorStrongPassword(t *testing.T) {
	evaluator, err := NewEvaluator(Policy{MinLength: 12})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	strength, findings := evaluator.Evaluate("Aa1!complexPASSXX")
	if strength != StrengthStrong {
		t.Fatalf("expected strong strength, got %s", strength)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestEvaluatorWeakPasswordDueToLength(t *testing.T) {
	evaluator, err := NewEvaluator(Policy{MinLength: 12})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	strength, findings := evaluator.Evaluate("Aa1!short")
	if strength != StrengthWeak {
		t.Fatalf("expected weak strength, got %s", strength)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings for weak password")
	}
}

func TestEvaluatorCommonPassword(t *testing.T) {
	evaluator, err := NewEvaluator(Policy{MinLength: 6})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	strength, findings := evaluator.Evaluate("password")
	if strength != StrengthWeak {
		t.Fatalf("expected weak strength for common password")
	}

	foundCommon := false
	for _, finding := range findings {
		if finding.Code == "password.common" {
			foundCommon = true
		}
	}
	if !foundCommon {
		t.Fatalf("expected common password finding")
	}
}
