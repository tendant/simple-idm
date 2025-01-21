package role

import (
	"context"

	"github.com/tendant/simple-idm/pkg/role/db"
)

type RoleService struct {
	queries *db.Queries
}

func NewRoleService(queries *db.Queries) *RoleService {
	return &RoleService{
		queries: queries,
	}
}

func (s *RoleService) FindRoles(ctx context.Context) ([]db.Role, error) {
	return s.queries.FindRoles(ctx)
}
