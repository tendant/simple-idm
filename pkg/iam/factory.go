package iam

import (
	"fmt"

	"github.com/tendant/simple-idm/pkg/iam/iamdb"
)

// RepositoryConfig contains configuration for creating IAM repositories
type RepositoryConfig struct {
	// Queries is required for PostgreSQL repositories
	Queries *iamdb.Queries
	// DataDir is required for file-based repositories
	DataDir string
}

// NewIamRepository creates a new IAM repository based on the persistence type
func NewIamRepository(persistenceType string, config RepositoryConfig) (IamRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Queries == nil {
			return nil, fmt.Errorf("queries required for postgres repository")
		}
		return NewPostgresIamRepository(config.Queries), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileIamRepository(config.DataDir)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}

// NewIamGroupRepository creates a new IAM group repository based on the persistence type
// For file-based storage, this requires an existing FileIamRepository
func NewIamGroupRepository(persistenceType string, config RepositoryConfig, iamRepo IamRepository) (IamGroupRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		if config.Queries == nil {
			return nil, fmt.Errorf("queries required for postgres repository")
		}
		return NewPostgresIamGroupRepository(config.Queries), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		// For file-based, we need the FileIamRepository
		fileIamRepo, ok := iamRepo.(*FileIamRepository)
		if !ok {
			return nil, fmt.Errorf("file-based group repository requires a FileIamRepository")
		}
		return NewFileIamGroupRepository(fileIamRepo), nil
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
