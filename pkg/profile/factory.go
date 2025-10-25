package profile

import (
	"fmt"

	"github.com/tendant/simple-idm/pkg/profile/profiledb"
)

// RepositoryConfig contains configuration for creating a profile repository
type RepositoryConfig struct {
	// Queries is required for PostgreSQL repositories
	Queries *profiledb.Queries
	// DataDir is required for file-based repositories
	DataDir string
}

// NewProfileRepository creates a new profile repository based on the persistence type
func NewProfileRepository(persistenceType string, config RepositoryConfig) (ProfileRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Queries == nil {
			return nil, fmt.Errorf("queries required for postgres repository")
		}
		return NewPostgresProfileRepository(config.Queries), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileProfileRepository(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
