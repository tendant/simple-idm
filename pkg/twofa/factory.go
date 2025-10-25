package twofa

import (
	"fmt"

	"github.com/tendant/simple-idm/pkg/twofa/twofadb"
)

// RepositoryConfig contains configuration for creating a 2FA repository
type RepositoryConfig struct {
	// Queries is required for PostgreSQL repositories
	Queries *twofadb.Queries
	// DataDir is required for file-based repositories
	DataDir string
}

// NewTwoFARepository creates a new 2FA repository based on the persistence type
func NewTwoFARepository(persistenceType string, config RepositoryConfig) (TwoFARepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Queries == nil {
			return nil, fmt.Errorf("queries required for postgres repository")
		}
		return NewPostgresTwoFARepository(config.Queries), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileTwoFARepository(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
