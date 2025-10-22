package pwned

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Dataset represents an embedded offline breach dataset backed by SHA-1 hashes.
type Dataset struct {
	name    string
	hashSet map[string]struct{}
}

// NewDataset constructs a Dataset from the supplied SHA-1 hashes.
func NewDataset(name string, hashes []string) (*Dataset, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("dataset name cannot be empty")
	}
	hashSet := make(map[string]struct{}, len(hashes))
	for i, hash := range hashes {
		trimmed := strings.ToUpper(strings.TrimSpace(hash))
		if trimmed == "" {
			continue
		}
		if len(trimmed) != 40 {
			return nil, fmt.Errorf("invalid SHA-1 hash at index %d", i)
		}
		if _, err := hex.DecodeString(trimmed); err != nil {
			return nil, fmt.Errorf("invalid SHA-1 hash at index %d: %w", i, err)
		}
		hashSet[trimmed] = struct{}{}
	}
	if len(hashSet) == 0 {
		return nil, errors.New("dataset must contain at least one hash entry")
	}
	return &Dataset{
		name:    name,
		hashSet: hashSet,
	}, nil
}

// IsBreached checks if the password is present in the dataset.
func (d *Dataset) IsBreached(ctx context.Context, password string) (bool, error) {
	if password == "" {
		return false, errors.New("password must not be empty")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
	hash := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))
	_, exists := d.hashSet[hashStr]
	return exists, nil
}

// Name returns the dataset source name.
func (d *Dataset) Name() string {
	return d.name
}
