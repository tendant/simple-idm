package impersonate

import (
	"context"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/mapper"
)

type DelegationRepository interface {
	FindDelegatedUsers(ctx context.Context, loginID uuid.UUID) ([]mapper.User, error)
}
