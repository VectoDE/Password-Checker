package pwned

import (
	"context"
	"errors"
	"fmt"
)

// Aggregator queries multiple breach data providers to improve coverage across official datasets.
type Aggregator struct {
	providers []Provider
}

// NewAggregator constructs a breach checker backed by multiple providers.
func NewAggregator(providers ...Provider) (*Aggregator, error) {
	if len(providers) == 0 {
		return nil, errors.New("at least one breach provider is required")
	}
	for i, provider := range providers {
		if provider == nil {
			return nil, fmt.Errorf("breach provider at index %d is nil", i)
		}
	}
	return &Aggregator{providers: providers}, nil
}

// IsBreached evaluates the supplied password against every configured provider.
func (a *Aggregator) IsBreached(ctx context.Context, password string) (bool, error) {
	if password == "" {
		return false, errors.New("password must not be empty")
	}
	var errs []error
	for _, provider := range a.providers {
		breached, err := provider.IsBreached(ctx, password)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", provider.Name(), err))
			continue
		}
		if breached {
			return true, nil
		}
	}
	if len(errs) == len(a.providers) {
		return false, fmt.Errorf("all breach providers failed: %w", errors.Join(errs...))
	}
	if len(errs) > 0 {
		return false, fmt.Errorf("some breach providers failed: %w", errors.Join(errs...))
	}
	return false, nil
}

// Name implements the Provider interface for the Aggregator itself.
func (a *Aggregator) Name() string {
	return "Aggregated Breach Providers"
}

// Providers exposes the configured providers (primarily for testing and observability).
func (a *Aggregator) Providers() []Provider {
	return append([]Provider(nil), a.providers...)
}
