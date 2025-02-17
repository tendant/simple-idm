package impersonate

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/impersonate/impersonatedb"
)

type ImpersonateService struct {
	queries *impersonatedb.Queries
}

func NewImpersonateService(queries *impersonatedb.Queries) *ImpersonateService {
	return &ImpersonateService{
		queries: queries,
	}
}

func (s *ImpersonateService) FindDelegatorRoles(ctx context.Context, userUuid uuid.UUID) ([]sql.NullString, error) {
	slog.Debug("FindDelegatorRoles", "userUuid", userUuid)
	roles, err := s.queries.FindUserRolesByUserUuid(ctx, userUuid)
	return roles, err
}
