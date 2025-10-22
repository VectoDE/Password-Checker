package pwned

import (
	"strings"

	_ "embed"
)

//go:embed datasets/global_sha1.txt
var globalDataset string

// NewGlobalDataset constructs a dataset representing a curated subset of official breach dumps.
func NewGlobalDataset() (*Dataset, error) {
	hashes := strings.Split(globalDataset, "\n")
	return NewDataset("Bundesweite & internationale behördliche Datenlecks", hashes)
}
