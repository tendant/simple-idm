package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tendant/simple-idm/pkg/client"
)

// TestCanManageTwoFactor tests the permission checking logic
func TestCanManageTwoFactor(t *testing.T) {
	handle := &Handle{}

	// Test user managing their own 2FA
	t.Run("user can manage own 2FA", func(t *testing.T) {
		loginID := uuid.New()
		authUser := &client.AuthUser{
			LoginID: loginID,
			ExtraClaims: client.ExtraClaims{
				Roles: []string{"user"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := context.WithValue(req.Context(), client.AuthUserKey, authUser)
		req = req.WithContext(ctx)

		canManage := handle.canManageTwoFactor(req, loginID)
		assert.True(t, canManage, "User should be able to manage their own 2FA")
	})

	// Test user trying to manage another user's 2FA without admin role
	t.Run("user cannot manage other user's 2FA", func(t *testing.T) {
		ownLoginID := uuid.New()
		otherLoginID := uuid.New()
		authUser := &client.AuthUser{
			LoginID: ownLoginID,
			ExtraClaims: client.ExtraClaims{
				Roles: []string{"user"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := context.WithValue(req.Context(), client.AuthUserKey, authUser)
		req = req.WithContext(ctx)

		canManage := handle.canManageTwoFactor(req, otherLoginID)
		assert.False(t, canManage, "User should not be able to manage another user's 2FA")
	})

	// Test admin managing another user's 2FA
	t.Run("admin can manage any user's 2FA", func(t *testing.T) {
		adminLoginID := uuid.New()
		targetLoginID := uuid.New()
		authUser := &client.AuthUser{
			LoginID: adminLoginID,
			ExtraClaims: client.ExtraClaims{
				Roles: []string{"admin"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := context.WithValue(req.Context(), client.AuthUserKey, authUser)
		req = req.WithContext(ctx)

		canManage := handle.canManageTwoFactor(req, targetLoginID)
		assert.True(t, canManage, "Admin should be able to manage any user's 2FA")
	})

	// Test superadmin managing another user's 2FA
	t.Run("superadmin can manage any user's 2FA", func(t *testing.T) {
		superadminLoginID := uuid.New()
		targetLoginID := uuid.New()
		authUser := &client.AuthUser{
			LoginID: superadminLoginID,
			ExtraClaims: client.ExtraClaims{
				Roles: []string{"superadmin"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := context.WithValue(req.Context(), client.AuthUserKey, authUser)
		req = req.WithContext(ctx)

		canManage := handle.canManageTwoFactor(req, targetLoginID)
		assert.True(t, canManage, "Superadmin should be able to manage any user's 2FA")
	})

	// Test missing auth user in context
	t.Run("missing auth user returns false", func(t *testing.T) {
		targetLoginID := uuid.New()
		req := httptest.NewRequest(http.MethodPost, "/", nil)

		canManage := handle.canManageTwoFactor(req, targetLoginID)
		assert.False(t, canManage, "Should return false when auth user is missing")
	})

	// Test user with multiple roles including admin
	t.Run("user with admin among multiple roles can manage any 2FA", func(t *testing.T) {
		userLoginID := uuid.New()
		targetLoginID := uuid.New()
		authUser := &client.AuthUser{
			LoginID: userLoginID,
			ExtraClaims: client.ExtraClaims{
				Roles: []string{"user", "admin", "moderator"},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := context.WithValue(req.Context(), client.AuthUserKey, authUser)
		req = req.WithContext(ctx)

		canManage := handle.canManageTwoFactor(req, targetLoginID)
		assert.True(t, canManage, "User with admin role should be able to manage any user's 2FA")
	})
}
