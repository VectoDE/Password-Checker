package password

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
)

const (
	lowerCharset = "abcdefghijklmnopqrstuvwxyz"
	upperCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitCharset = "0123456789"
)

// GeneratorPolicy defines constraints for password generation.
type GeneratorPolicy struct {
	MinLength        int
	BitsPerCharacter float64
	SpecialCharset   string
}

// Generator produces cryptographically secure passwords.
type Generator struct {
	policy  GeneratorPolicy
	charset []rune
}

// NewGenerator constructs a password generator with the provided policy.
func NewGenerator(policy GeneratorPolicy) (*Generator, error) {
	if policy.MinLength <= 0 {
		return nil, errors.New("minimum length must be greater than zero")
	}
	if policy.BitsPerCharacter <= 0 {
		return nil, errors.New("bits per character must be greater than zero")
	}
	if policy.SpecialCharset == "" {
		return nil, errors.New("special character set cannot be empty")
	}

	charset := []rune(lowerCharset + upperCharset + digitCharset + policy.SpecialCharset)

	return &Generator{
		policy:  policy,
		charset: charset,
	}, nil
}

// Generate returns a password with at least the requested entropy in bits.
func (g *Generator) Generate(bits int) (string, error) {
	if bits <= 0 {
		return "", errors.New("bits must be greater than zero")
	}

	length := int(math.Ceil(float64(bits) / g.policy.BitsPerCharacter))
	if length < g.policy.MinLength {
		length = g.policy.MinLength
	}

	password := make([]rune, length)

	// Ensure inclusion of characters from each category.
	requiredSets := []string{lowerCharset, upperCharset, digitCharset, g.policy.SpecialCharset}
	if length < len(requiredSets) {
		return "", fmt.Errorf("password length %d insufficient to satisfy required character sets", length)
	}

	idx := 0
	for _, set := range requiredSets {
		r, err := randomRuneFrom(set)
		if err != nil {
			return "", err
		}
		password[idx] = r
		idx++
	}

	for idx < length {
		r, err := randomRuneFromRunes(g.charset)
		if err != nil {
			return "", err
		}
		password[idx] = r
		idx++
	}

	// Shuffle the password to remove predictable ordering of required characters.
	if err := shuffleRunes(password); err != nil {
		return "", err
	}

	return string(password), nil
}

func randomRuneFrom(set string) (rune, error) {
	return randomRuneFromRunes([]rune(set))
}

func randomRuneFromRunes(runes []rune) (rune, error) {
	n := len(runes)
	if n == 0 {
		return 0, errors.New("rune set cannot be empty")
	}

	index, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random index: %w", err)
	}
	return runes[index.Int64()], nil
}

func shuffleRunes(runes []rune) error {
	for i := len(runes) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("failed to shuffle password: %w", err)
		}
		j := int(jBig.Int64())
		runes[i], runes[j] = runes[j], runes[i]
	}
	return nil
}
