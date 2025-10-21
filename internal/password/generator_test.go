package password

import "testing"

func TestNewGeneratorValidation(t *testing.T) {
	_, err := NewGenerator(GeneratorPolicy{MinLength: 0, BitsPerCharacter: 5.9, SpecialCharset: "!"})
	if err == nil {
		t.Fatalf("expected error for invalid min length")
	}
}

func TestGenerateProducesSecurePassword(t *testing.T) {
	generator, err := NewGenerator(GeneratorPolicy{MinLength: 16, BitsPerCharacter: 5.95, SpecialCharset: "!@"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	password, err := generator.Generate(128)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(password) < 16 {
		t.Fatalf("expected password length >= 16, got %d", len(password))
	}

	if !containsAny(password, lowerCharset) {
		t.Fatalf("expected lowercase characters in generated password")
	}
	if !containsAny(password, upperCharset) {
		t.Fatalf("expected uppercase characters in generated password")
	}
	if !containsAny(password, digitCharset) {
		t.Fatalf("expected digits in generated password")
	}
	if !containsAny(password, "!@") {
		t.Fatalf("expected special characters in generated password")
	}
}

func TestGenerateRejectsInvalidBits(t *testing.T) {
	generator, err := NewGenerator(GeneratorPolicy{MinLength: 16, BitsPerCharacter: 5.95, SpecialCharset: "!@"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := generator.Generate(0); err == nil {
		t.Fatalf("expected error when bits <= 0")
	}
}

func containsAny(value, charset string) bool {
	for _, r := range value {
		for _, c := range charset {
			if r == c {
				return true
			}
		}
	}
	return false
}
