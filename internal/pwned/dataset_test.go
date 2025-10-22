package pwned

import (
	"context"
	"testing"
)

func TestNewDatasetValidation(t *testing.T) {
	if _, err := NewDataset("", nil); err == nil {
		t.Fatalf("expected error when dataset name is empty")
	}
	if _, err := NewDataset("sample", []string{"invalid"}); err == nil {
		t.Fatalf("expected error for invalid hash")
	}
	if _, err := NewDataset("sample", []string{}); err == nil {
		t.Fatalf("expected error when dataset is empty")
	}
}

func TestDatasetMatch(t *testing.T) {
	dataset, err := NewDataset("test", []string{"7C4A8D09CA3762AF61E59520943DC26494F8941B"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	breached, err := dataset.IsBreached(context.Background(), "123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !breached {
		t.Fatalf("expected dataset to report breach")
	}
	breached, err = dataset.IsBreached(context.Background(), "different")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Fatalf("expected dataset to report no breach")
	}
}

func TestNewGlobalDataset(t *testing.T) {
	dataset, err := NewGlobalDataset()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dataset.Name() == "" {
		t.Fatalf("expected dataset name to be populated")
	}
}
