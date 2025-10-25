package auth

import (
	"fmt"

	"github.com/tendant/simple-idm/pkg/auth/db"
)

// RepositoryConfig contains configuration for creating an auth repository
type RepositoryConfig struct {
	// Queries is required for PostgreSQL repositories
	Queries *db.Queries
	// DataDir is required for file-based repositories
	DataDir string
}

// NewAuthRepository creates a new auth repository based on the persistence type
func NewAuthRepository(persistenceType string, config RepositoryConfig) (AuthRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Queries == nil {
			return nil, fmt.Errorf("queries required for postgres repository")
		}
		return NewPostgresAuthRepository(config.Queries), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileAuthRepository(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
