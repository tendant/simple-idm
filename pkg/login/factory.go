package login

import (
	"fmt"

	"github.com/tendant/simple-idm/pkg/login/logindb"
)

// RepositoryConfig contains configuration for creating a login repository
type RepositoryConfig struct {
	// Queries is required for PostgreSQL repositories
	Queries *logindb.Queries
	// DataDir is required for file-based repositories
	DataDir string
}

// NewLoginRepository creates a new login repository based on the persistence type
func NewLoginRepository(persistenceType string, config RepositoryConfig) (LoginRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Queries == nil {
			return nil, fmt.Errorf("queries required for postgres repository")
		}
		return NewPostgresLoginRepository(config.Queries), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileLoginRepository(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
