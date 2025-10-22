package pwned

import "context"

// Provider represents a breach data source capable of evaluating a password.
type Provider interface {
	Name() string
	IsBreached(ctx context.Context, password string) (bool, error)
}
