package impersonate

import (
	"context"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/mapper"
)

type DelegationRepository interface {
	FindDelegators(ctx context.Context, delegateeUuid uuid.UUID) ([]mapper.User, error)
}
