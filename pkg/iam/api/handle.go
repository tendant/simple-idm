package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/iam"
	"golang.org/x/exp/slog"
)

type Handle struct {
	iamService *iam.IamService
}

func NewHandle(iamService *iam.IamService) Handle {
	return Handle{
		iamService: iamService,
	}
}

type CreateUserRequest struct {
	Name     *string     `json:"name"`
	Email    string      `json:"email"`
	Username string      `json:"username"`
	RoleIds  []uuid.UUID `json:"role_ids"`
	LoginID  *string     `json:"login_id"`
}

type UpdateUserRequest struct {
	Name    *string     `json:"name"`
	RoleIds []uuid.UUID `json:"role_ids"`
	LoginID *string     `json:"login_id"`
}

type CreateGroupRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

type UpdateGroupRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type AddUserToGroupRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

type RemoveUserFromGroupRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

// Get a list of users
// (GET /)
func (h Handle) Get(w http.ResponseWriter, r *http.Request) *Response {
	users, err := h.iamService.FindUsers(r.Context())
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": "Failed to find users"},
		}
	}

	// Convert users to response format
	var response []struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID      *string `json:"id,omitempty"`
		LoginID string  `json:"login_id,omitempty"`
	}

	for _, user := range users {
		idStr := user.ID.String()
		var namePtr *string
		if user.Name != "" {
			namePtr = &user.Name
		}

		// Handle roles
		var roles []struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		}
		if len(user.Roles) > 0 {
			for _, role := range user.Roles {
				idStr := role.ID.String()
				roles = append(roles, struct {
					Name *string `json:"name,omitempty"`
					ID   *string `json:"id,omitempty"`
				}{
					Name: &role.Name,
					ID:   &idStr,
				})
			}
		}

		response = append(response, struct {
			Email    *string `json:"email,omitempty"`
			Username *string `json:"username,omitempty"`
			Name     *string `json:"name,omitempty"`
			Roles    []struct {
				Name *string `json:"name,omitempty"`
				ID   *string `json:"id,omitempty"`
			} `json:"roles,omitempty"`
			ID      *string `json:"id,omitempty"`
			LoginID string  `json:"login_id,omitempty"`
		}{
			Email:    &user.Email,
			Username: &user.Username,
			Name:     namePtr,
			Roles:    roles,
			ID:       &idStr,
			LoginID:  getLoginIDString(user.LoginID),
		})
	}

	return &Response{
		Code: http.StatusOK,
		body: response,
	}
}

func getLoginIDString(loginID *uuid.UUID) string {
	if loginID != nil {
		return loginID.String()
	}
	return ""
}

// Create a new user
// (POST /)
func (h Handle) Post(w http.ResponseWriter, r *http.Request) *Response {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid request body"},
		}
	}

	name := ""
	if req.Name != nil {
		name = *req.Name
	}

	loginID := ""
	if req.LoginID != nil {
		loginID = *req.LoginID
	}

	user, err := h.iamService.CreateUser(r.Context(), req.Email, req.Username, name, req.RoleIds, loginID)
	if err != nil {
		slog.Error("Failed to create user", "error", err, "roleIds", req.RoleIds)
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": fmt.Sprintf("Failed to create user: %v", err)},
		}
	}

	idStr := user.ID.String()
	var namePtr *string
	if user.Name != "" {
		namePtr = &user.Name
	}
	// Username field removed as it doesn't exist in the struct
	// usernamePtr := &user.Username.String
	// if !user.Username.Valid {
	// 	usernamePtr = nil
	// }

	response := struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID *string `json:"id,omitempty"`
	}{
		Email: &user.Email,
		// Username field removed as it doesn't exist in the struct
		Name: namePtr,
		ID:   &idStr,
	}

	// Convert roles from domain model to response format
	var roles []struct {
		Name *string `json:"name,omitempty"`
		ID   *string `json:"id,omitempty"`
	}
	for _, role := range user.Roles {
		idStr := role.ID.String()
		roles = append(roles, struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		}{
			Name: &role.Name,
			ID:   &idStr,
		})
	}
	response.Roles = roles

	return &Response{
		Code: http.StatusCreated,
		body: response,
	}
}

// Get user details by UUID
// (GET /{id})
func (h Handle) GetID(w http.ResponseWriter, r *http.Request, id string) *Response {
	userUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	user, err := h.iamService.GetUser(r.Context(), userUuid)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": "Failed to get user"},
		}
	}

	idStr := user.ID.String()
	var namePtr *string
	if user.Name != "" {
		namePtr = &user.Name
	}
	// Username field removed as it doesn't exist in the struct
	// usernamePtr := &user.Username.String
	// if !user.Username.Valid {
	// 	usernamePtr = nil
	// }
	responseUser := struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID      *string `json:"id,omitempty"`
		LoginID string  `json:"login_id,omitempty"`
	}{
		Email:    &user.Email,
		Username: &user.Username,
		Name:     namePtr,
		ID:       &idStr,
		LoginID:  getLoginIDString(user.LoginID),
	}

	// Convert roles from domain model to response format
	var roles []struct {
		Name *string `json:"name,omitempty"`
		ID   *string `json:"id,omitempty"`
	}
	for _, role := range user.Roles {
		idStr := role.ID.String()
		roles = append(roles, struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		}{
			Name: &role.Name,
			ID:   &idStr,
		})
	}
	responseUser.Roles = roles

	return &Response{
		Code: http.StatusOK,
		body: responseUser,
	}
}

// Update user details by UUID
// (PUT /{id})
func (h Handle) PutID(w http.ResponseWriter, r *http.Request, id string) *Response {
	userUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	var request UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid request body"},
		}
	}

	name := ""
	if request.Name != nil {
		name = *request.Name
	}

	// Parse login ID if provided
	var loginIdPtr *uuid.UUID
	if request.LoginID != nil && *request.LoginID != "" {
		loginId, err := uuid.Parse(*request.LoginID)
		if err != nil {
			return &Response{
				Code: http.StatusBadRequest,
				body: map[string]string{"error": "Invalid login ID format"},
			}
		}
		loginIdPtr = &loginId
	}

	user, err := h.iamService.UpdateUser(r.Context(), userUuid, name, request.RoleIds, loginIdPtr)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": fmt.Sprintf("Failed to update user: %v", err)},
		}
	}

	idStrPtr := user.ID.String()
	var namePtr *string
	if user.Name != "" {
		namePtr = &user.Name
	}
	// Username field removed as it doesn't exist in the struct
	// usernamePtr := &user.Username.String
	// if !user.Username.Valid {
	// 	usernamePtr = nil
	// }
	responseUser := struct {
		Email    *string `json:"email,omitempty"`
		Username *string `json:"username,omitempty"`
		Name     *string `json:"name,omitempty"`
		Roles    []struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		} `json:"roles,omitempty"`
		ID *string `json:"id,omitempty"`
	}{
		Email: &user.Email,
		// Username field removed as it doesn't exist in the struct
		Name: namePtr,
		ID:   &idStrPtr,
	}

	// Convert roles from domain model to response format
	var roles []struct {
		Name *string `json:"name,omitempty"`
		ID   *string `json:"id,omitempty"`
	}
	for _, role := range user.Roles {
		idStr := role.ID.String()
		roles = append(roles, struct {
			Name *string `json:"name,omitempty"`
			ID   *string `json:"id,omitempty"`
		}{
			Name: &role.Name,
			ID:   &idStr,
		})
	}
	responseUser.Roles = roles

	return &Response{
		Code: http.StatusOK,
		body: responseUser,
	}
}

// Delete user by UUID
// (DELETE /{uuid})
func (h Handle) DeleteID(w http.ResponseWriter, r *http.Request, uuidStr string) *Response {
	userUuid, err := uuid.Parse(uuidStr)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	err = h.iamService.DeleteUser(r.Context(), userUuid)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": "Failed to delete user"},
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{"message": "User deleted successfully"},
	}
}

// Get a list of groups
// (GET /groups)
func (h Handle) GetGroups(w http.ResponseWriter, r *http.Request) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	groups, err := h.iamService.FindGroups(r.Context())
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": "Failed to find groups"},
		}
	}

	// Convert groups to response format
	var response []struct {
		CreatedAt   *time.Time `json:"created_at,omitempty"`
		Description *string    `json:"description,omitempty"`
		ID          *string    `json:"id,omitempty"`
		Name        *string    `json:"name,omitempty"`
		UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	}

	for _, group := range groups {
		idStr := group.ID.String()
		var descPtr *string
		if group.Description != "" {
			descPtr = &group.Description
		}

		response = append(response, struct {
			CreatedAt   *time.Time `json:"created_at,omitempty"`
			Description *string    `json:"description,omitempty"`
			ID          *string    `json:"id,omitempty"`
			Name        *string    `json:"name,omitempty"`
			UpdatedAt   *time.Time `json:"updated_at,omitempty"`
		}{
			ID:          &idStr,
			Name:        &group.Name,
			Description: descPtr,
			CreatedAt:   &group.CreatedAt,
			UpdatedAt:   &group.UpdatedAt,
		})
	}

	return GetGroupsJSON200Response(response)
}

// Create a new group
// (POST /groups)
func (h Handle) PostGroups(w http.ResponseWriter, r *http.Request) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid request body"},
		}
	}

	description := ""
	if req.Description != nil {
		description = *req.Description
	}

	group, err := h.iamService.CreateGroup(r.Context(), req.Name, description)
	if err != nil {
		slog.Error("Failed to create group", "error", err, "name", req.Name)
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": fmt.Sprintf("Failed to create group: %v", err)},
		}
	}

	idStr := group.ID.String()
	var descPtr *string
	if group.Description != "" {
		descPtr = &group.Description
	}

	response := struct {
		CreatedAt   *time.Time `json:"created_at,omitempty"`
		Description *string    `json:"description,omitempty"`
		ID          *string    `json:"id,omitempty"`
		Name        *string    `json:"name,omitempty"`
		UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	}{
		ID:          &idStr,
		Name:        &group.Name,
		Description: descPtr,
		CreatedAt:   &group.CreatedAt,
		UpdatedAt:   &group.UpdatedAt,
	}

	return PostGroupsJSON200Response(response)
}

// Get group details by UUID
// (GET /groups/{id})
func (h Handle) GetGroupsID(w http.ResponseWriter, r *http.Request, id string) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	groupUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	group, err := h.iamService.GetGroup(r.Context(), groupUuid)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": "Failed to get group"},
		}
	}

	idStr := group.ID.String()
	var descPtr *string
	if group.Description != "" {
		descPtr = &group.Description
	}

	response := struct {
		CreatedAt   *time.Time `json:"created_at,omitempty"`
		Description *string    `json:"description,omitempty"`
		ID          *string    `json:"id,omitempty"`
		Name        *string    `json:"name,omitempty"`
		UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	}{
		ID:          &idStr,
		Name:        &group.Name,
		Description: descPtr,
		CreatedAt:   &group.CreatedAt,
		UpdatedAt:   &group.UpdatedAt,
	}

	return GetGroupsIDJSON200Response(response)
}

// Update group details by UUID
// (PUT /groups/{id})
func (h Handle) PutGroupsID(w http.ResponseWriter, r *http.Request, id string) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	groupUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	var request UpdateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid request body"},
		}
	}

	name := ""
	if request.Name != nil {
		name = *request.Name
	}

	description := ""
	if request.Description != nil {
		description = *request.Description
	}

	group, err := h.iamService.UpdateGroup(r.Context(), groupUuid, name, description)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": fmt.Sprintf("Failed to update group: %v", err)},
		}
	}

	idStr := group.ID.String()
	var descPtr *string
	if group.Description != "" {
		descPtr = &group.Description
	}

	response := struct {
		CreatedAt   *time.Time `json:"created_at,omitempty"`
		Description *string    `json:"description,omitempty"`
		ID          *string    `json:"id,omitempty"`
		Name        *string    `json:"name,omitempty"`
		UpdatedAt   *time.Time `json:"updated_at,omitempty"`
	}{
		ID:          &idStr,
		Name:        &group.Name,
		Description: descPtr,
		CreatedAt:   &group.CreatedAt,
		UpdatedAt:   &group.UpdatedAt,
	}

	return PutGroupsIDJSON200Response(response)
}

// Delete group by UUID
// (DELETE /groups/{id})
func (h Handle) DeleteGroupsID(w http.ResponseWriter, r *http.Request, id string) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	groupUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	err = h.iamService.DeleteGroup(r.Context(), groupUuid)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": "Failed to delete group"},
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{"message": "Group deleted successfully"},
	}
}

// Get users in a group
// (GET /groups/{id}/users)
func (h Handle) GetGroupsIDUsers(w http.ResponseWriter, r *http.Request, id string) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	groupUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid UUID format"},
		}
	}

	users, err := h.iamService.FindGroupUsers(r.Context(), groupUuid)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": "Failed to find group users"},
		}
	}

	// Convert users to response format
	var response []struct {
		Email    *string `json:"email,omitempty"`
		ID       *string `json:"id,omitempty"`
		Name     *string `json:"name,omitempty"`
		Username *string `json:"username,omitempty"`
	}

	for _, user := range users {
		idStr := user.ID.String()
		var namePtr *string
		if user.Name != "" {
			namePtr = &user.Name
		}

		response = append(response, struct {
			Email    *string `json:"email,omitempty"`
			ID       *string `json:"id,omitempty"`
			Name     *string `json:"name,omitempty"`
			Username *string `json:"username,omitempty"`
		}{
			ID:       &idStr,
			Email:    &user.Email,
			Username: &user.Username,
			Name:     namePtr,
		})
	}

	return GetGroupsIDUsersJSON200Response(response)
}

// Add user to group
// (POST /groups/{id}/users)
func (h Handle) PostGroupsIDUsers(w http.ResponseWriter, r *http.Request, id string) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	groupUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid group UUID format"},
		}
	}

	var req AddUserToGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid request body"},
		}
	}

	err = h.iamService.AddUserToGroup(r.Context(), req.UserID, groupUuid)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": fmt.Sprintf("Failed to add user to group: %v", err)},
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{"message": "User added to group successfully"},
	}
}

// Remove user from group
// (DELETE /groups/{id}/users)
func (h Handle) DeleteGroupsIDUsers(w http.ResponseWriter, r *http.Request, id string) *Response {
	if !h.iamService.HasGroupSupport() {
		return &Response{
			Code: http.StatusNotImplemented,
			body: map[string]string{"error": "Groups not supported"},
		}
	}

	groupUuid, err := uuid.Parse(id)
	if err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid group UUID format"},
		}
	}

	var req RemoveUserFromGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return &Response{
			Code: http.StatusBadRequest,
			body: map[string]string{"error": "Invalid request body"},
		}
	}

	err = h.iamService.RemoveUserFromGroup(r.Context(), req.UserID, groupUuid)
	if err != nil {
		return &Response{
			Code: http.StatusInternalServerError,
			body: map[string]string{"error": fmt.Sprintf("Failed to remove user from group: %v", err)},
		}
	}

	return &Response{
		Code: http.StatusOK,
		body: map[string]string{"message": "User removed from group successfully"},
	}
}
