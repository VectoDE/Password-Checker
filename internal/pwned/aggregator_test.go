package pwned

import (
	"context"
	"errors"
	"testing"
)

type stubProvider struct {
	name   string
	result bool
	err    error
}

func (s stubProvider) Name() string {
	return s.name
}

func (s stubProvider) IsBreached(ctx context.Context, password string) (bool, error) {
	return s.result, s.err
}

func TestNewAggregatorValidation(t *testing.T) {
	if _, err := NewAggregator(); err == nil {
		t.Fatalf("expected error when no providers are supplied")
	}
	if _, err := NewAggregator(nil); err == nil {
		t.Fatalf("expected error when provider is nil")
	}
}

func TestAggregatorPositiveMatch(t *testing.T) {
	agg, err := NewAggregator(
		stubProvider{name: "hibp", result: false},
		stubProvider{name: "official", result: true},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	breached, err := agg.IsBreached(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !breached {
		t.Fatalf("expected breach to be detected")
	}
}

func TestAggregatorErrorsWhenAllProvidersFail(t *testing.T) {
	agg, err := NewAggregator(
		stubProvider{name: "hibp", err: errors.New("timeout")},
		stubProvider{name: "official", err: errors.New("unavailable")},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := agg.IsBreached(context.Background(), "password"); err == nil {
		t.Fatalf("expected error when all providers fail")
	}
}

func TestAggregatorPartialFailuresSurface(t *testing.T) {
	agg, err := NewAggregator(
		stubProvider{name: "hibp", err: errors.New("timeout")},
		stubProvider{name: "official", result: false},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := agg.IsBreached(context.Background(), "password"); err == nil {
		t.Fatalf("expected error when some providers fail")
	}
}

func TestAggregatorNegative(t *testing.T) {
	agg, err := NewAggregator(
		stubProvider{name: "hibp", result: false},
		stubProvider{name: "official", result: false},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	breached, err := agg.IsBreached(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Fatalf("expected no breach to be detected")
	}
}
