package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// PasswordStore defines persistence operations for stored passwords.
type PasswordStore interface {
	Save(label, password string) (StoredPassword, error)
	List() ([]StoredPassword, error)
}

// StoredPassword represents a credential persisted in the store.
type StoredPassword struct {
	Label     string    `json:"label"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FileStore persists passwords on disk using a JSON file.
type FileStore struct {
	path     string
	lockPath string
	mu       sync.Mutex
}

// NewFileStore initialises a password store that writes to the provided path.
func NewFileStore(path string) (PasswordStore, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("storage path cannot be empty")
	}

	directory := filepath.Dir(trimmed)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	if err := ensureFileInitialised(trimmed); err != nil {
		return nil, err
	}

	return &FileStore{
		path:     trimmed,
		lockPath: trimmed + ".lock",
	}, nil
}

// Save stores or updates a password under the provided label.
func (s *FileStore) Save(label, password string) (StoredPassword, error) {
	cleanLabel := strings.TrimSpace(label)
	if cleanLabel == "" {
		return StoredPassword{}, errors.New("label cannot be empty")
	}
	if password == "" {
		return StoredPassword{}, errors.New("password cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := s.acquireFileLock()
	if err != nil {
		return StoredPassword{}, err
	}
	defer s.releaseFileLock(lock)

	entries, err := s.readAll()
	if err != nil {
		return StoredPassword{}, err
	}

	now := time.Now().UTC()
	for idx := range entries {
		if strings.EqualFold(entries[idx].Label, cleanLabel) {
			entries[idx].Label = cleanLabel
			entries[idx].Password = password
			entries[idx].UpdatedAt = now
			if err := s.writeAll(entries); err != nil {
				return StoredPassword{}, err
			}
			return entries[idx], nil
		}
	}

	record := StoredPassword{
		Label:     cleanLabel,
		Password:  password,
		CreatedAt: now,
		UpdatedAt: now,
	}
	entries = append(entries, record)
	if err := s.writeAll(entries); err != nil {
		return StoredPassword{}, err
	}

	return record, nil
}

// List retrieves all stored passwords sorted alphabetically by label.
func (s *FileStore) List() ([]StoredPassword, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.readAll()
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Label) < strings.ToLower(entries[j].Label)
	})

	return entries, nil
}

func ensureFileInitialised(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to access storage file: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create storage file: %w", err)
	}
	defer file.Close()

	initial := struct {
		Entries []StoredPassword `json:"entries"`
	}{Entries: []StoredPassword{}}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(initial); err != nil {
		return fmt.Errorf("failed to initialise storage file: %w", err)
	}
	return nil
}

func (s *FileStore) readAll() ([]StoredPassword, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage file: %w", err)
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		return []StoredPassword{}, nil
	}

	var payload struct {
		Entries []StoredPassword `json:"entries"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("failed to decode storage file: %w", err)
	}
	if payload.Entries == nil {
		return []StoredPassword{}, nil
	}
	return payload.Entries, nil
}

func (s *FileStore) acquireFileLock() (*os.File, error) {
	for {
		lockFile, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return lockFile, nil
		}
		if errors.Is(err, os.ErrExist) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil, fmt.Errorf("failed to acquire storage lock: %w", err)
	}
}

func (s *FileStore) releaseFileLock(lockFile *os.File) {
	if lockFile == nil {
		return
	}
	lockFile.Close()
	os.Remove(s.lockPath)
}

func (s *FileStore) writeAll(entries []StoredPassword) error {
	tempFile, err := os.CreateTemp(filepath.Dir(s.path), "password-store-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary storage file: %w", err)
	}

	encoder := json.NewEncoder(tempFile)
	encoder.SetIndent("", "  ")
	payload := struct {
		Entries []StoredPassword `json:"entries"`
	}{Entries: entries}
	if err := encoder.Encode(payload); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return fmt.Errorf("failed to write storage data: %w", err)
	}

	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return fmt.Errorf("failed to set storage permissions: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		os.Remove(tempFile.Name())
		return fmt.Errorf("failed to close temporary storage file: %w", err)
	}

	if err := os.Rename(tempFile.Name(), s.path); err != nil {
		os.Remove(tempFile.Name())
		return fmt.Errorf("failed to replace storage file: %w", err)
	}

	return nil
}
