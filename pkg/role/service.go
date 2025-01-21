package role

import (
	"context"

	"github.com/tendant/simple-idm/pkg/role/roledb"
)

type RoleService struct {
	queries *roledb.Queries
}

func NewRoleService(queries *roledb.Queries) *RoleService {
	return &RoleService{
		queries: queries,
	}
}

func (s *RoleService) FindRoles(ctx context.Context) ([]roledb.FindRolesRow, error) {
	return s.queries.FindRoles(ctx)
}
