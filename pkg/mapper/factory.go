package mapper

import (
	"fmt"

	"github.com/tendant/simple-idm/pkg/mapper/mapperdb"
)

// RepositoryConfig contains configuration for creating a mapper repository
type RepositoryConfig struct {
	// Queries is required for PostgreSQL repositories
	Queries *mapperdb.Queries
	// DataDir is required for file-based repositories
	DataDir string
}

// NewMapperRepository creates a new mapper repository based on the persistence type
func NewMapperRepository(persistenceType string, config RepositoryConfig) (MapperRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Queries == nil {
			return nil, fmt.Errorf("queries required for postgres repository")
		}
		return NewPostgresMapperRepository(config.Queries), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileMapperRepository(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
