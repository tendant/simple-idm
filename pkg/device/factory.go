package device

import (
	"fmt"
)

// RepositoryConfig contains configuration for creating a device repository
type RepositoryConfig struct {
	// DB is required for PostgreSQL repositories (DBTX interface)
	DB DBTX
	// DataDir is required for file-based repositories
	DataDir string
	// Options for device repository (expiry duration, etc.)
	// If not provided, DefaultDeviceRepositoryOptions() will be used
	Options *DeviceRepositoryOptions
}

// NewDeviceRepository creates a new device repository based on the persistence type
func NewDeviceRepository(persistenceType string, config RepositoryConfig) (DeviceRepository, error) {
	// Get options or use defaults
	options := DefaultDeviceRepositoryOptions()
	if config.Options != nil {
		options = *config.Options
	}

	switch persistenceType {
	case "postgres", "postgresql":
		if config.DB == nil {
			return nil, fmt.Errorf("db required for postgres repository")
		}
		return NewPostgresDeviceRepositoryWithOptions(config.DB, options), nil
	case "file":
		if config.DataDir == "" {
			return nil, fmt.Errorf("dataDir required for file repository")
		}
		return NewFileDeviceRepository(config.DataDir, options)
	default:
		return nil, fmt.Errorf("unsupported persistence type: %s (supported: postgres, file)", persistenceType)
	}
}
