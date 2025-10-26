package emailverification

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RepositoryConfig contains configuration for creating an email verification repository
type RepositoryConfig struct {
	// Pool is required for PostgreSQL repositories
	Pool *pgxpool.Pool
	// DataDir is required for file-based repositories
	DataDir string
}

// NewEmailVerificationRepository creates a new email verification repository based on the persistence type
func NewEmailVerificationRepository(persistenceType string, config RepositoryConfig) (EmailVerificationRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Pool == nil {
			return nil, fmt.Errorf("pool required for postgres repository")
		}
		// The existing Repository struct implements EmailVerificationRepository interface
		return NewRepository(config.Pool), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileEmailVerificationRepository(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
