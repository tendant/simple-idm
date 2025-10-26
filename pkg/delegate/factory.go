package delegate

import (
	"fmt"

	"github.com/tendant/simple-idm/pkg/mapper"
)

// RepositoryConfig contains configuration for creating a delegation repository
type RepositoryConfig struct {
	// DataDir is required for file-based repositories
	DataDir string
	// UserMapper is required for looking up user information
	UserMapper mapper.UserMapper
}

// NewDelegationRepository creates a new delegation repository based on the persistence type
// Note: Currently only file-based implementation is available
func NewDelegationRepository(persistenceType string, config RepositoryConfig) (DelegationRepository, error) {
	switch persistenceType {
	case "postgres", "postgresql":
		return nil, fmt.Errorf("postgres repository not implemented for delegation (only file-based is available)")
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		if config.UserMapper == nil {
			return nil, fmt.Errorf("userMapper required for delegation repository")
		}
		return NewFileDelegationRepository(config.DataDir, config.UserMapper)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: file)", persistenceType)
	}
}
