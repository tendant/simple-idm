package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm/pkg/client"
	"github.com/tendant/simple-idm/pkg/device"
)

// DeviceHandler handles HTTP requests for device management
type DeviceHandler struct {
	deviceService *device.DeviceService
}

// NewDeviceHandler creates a new device handler
func NewDeviceHandler(deviceService *device.DeviceService) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
	}
}

// CreateDeviceRequest represents the request body for creating a device
type CreateDeviceRequest struct {
	Fingerprint string `json:"fingerprint"`
	UserAgent   string `json:"user_agent"`
}

// CreateDeviceResponse represents the response body for creating a device
type CreateDeviceResponse struct {
	Status  string        `json:"status"`
	Message string        `json:"message"`
	Device  device.Device `json:"device"`
}

// LinkDeviceRequest represents the request body for linking a device to a login
type LinkDeviceRequest struct {
	Fingerprint string `json:"fingerprint"`
	LoginID     string `json:"login_id,omitempty"`
}

// LinkDeviceResponse represents the response body for linking a device to a login
type LinkDeviceResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	ExpiresAt string `json:"expires_at"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// DeviceWithLogin represents a device with its linked login information
type DeviceWithLogin struct {
	device.Device
	LinkedLogins []LoginInfo `json:"linked_logins,omitempty"`
	ExpiresAt    string      `json:"expires_at,omitempty"` // When the device-login link expires
}

// LoginInfo represents basic login information
type LoginInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// ListDevicesResponse represents the response body for listing devices
type ListDevicesResponse struct {
	Status  string            `json:"status"`
	Message string            `json:"message"`
	Devices []DeviceWithLogin `json:"devices"`
}

// ListDevices handles listing all devices
func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	// Get all devices
	devices, err := h.deviceService.FindAllDevices(r.Context())
	if err != nil {
		slog.Error("Failed to get devices", "error", err)
		renderErrorResponse(w, r, http.StatusInternalServerError, "Failed to get devices", err.Error())
		return
	}

	// Get login information for each device
	devicesWithLogin := make([]DeviceWithLogin, 0, len(devices))
	for _, d := range devices {
		deviceWithLogin := DeviceWithLogin{
			Device: d,
		}

		// Get linked logins for this device
		linkedLogins, err := h.deviceService.FindLoginsByDevice(r.Context(), d.Fingerprint)
		if err != nil {
			slog.Error("Failed to get linked logins for device", "fingerprint", d.Fingerprint, "error", err)
			// Continue with other devices even if we can't get login info for this one
			devicesWithLogin = append(devicesWithLogin, deviceWithLogin)
			continue
		}

		// Add login info to the response
		loginInfos := make([]LoginInfo, 0, len(linkedLogins))
		for _, login := range linkedLogins {
			loginInfos = append(loginInfos, LoginInfo{
				ID:       login.ID.String(),
				Username: login.Username,
			})
		}
		deviceWithLogin.LinkedLogins = loginInfos

		devicesWithLogin = append(devicesWithLogin, deviceWithLogin)
	}

	// Return success response
	response := ListDevicesResponse{
		Status:  "success",
		Message: "Devices retrieved successfully",
		Devices: devicesWithLogin,
	}
	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// CreateDevice handles the creation of a new device
func (h *DeviceHandler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req CreateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		renderErrorResponse(w, r, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if req.Fingerprint == "" {
		renderErrorResponse(w, r, http.StatusBadRequest, "Missing required field", "fingerprint is required")
		return
	}

	// If UserAgent is not provided, use the one from the request
	if req.UserAgent == "" {
		req.UserAgent = r.UserAgent()
	}

	// Create device
	createdDevice, err := h.deviceService.RegisterDevice(r.Context(), req.Fingerprint, req.UserAgent)
	if err != nil {
		slog.Error("Failed to register device", "error", err)
		renderErrorResponse(w, r, http.StatusInternalServerError, "Failed to register device", err.Error())
		return
	}

	// Return success response
	response := CreateDeviceResponse{
		Status:  "success",
		Message: "Device registered successfully",
		Device:  createdDevice,
	}
	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// LinkDeviceToLogin handles linking a device to a login
func (h *DeviceHandler) LinkDeviceToLogin(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok || authUser == nil {
		renderErrorResponse(w, r, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	// Parse request body
	var req LinkDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Failed to decode request body", "error", err)
		renderErrorResponse(w, r, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if req.Fingerprint == "" {
		renderErrorResponse(w, r, http.StatusBadRequest, "Missing required field", "fingerprint is required")
		return
	}

	// Determine which login ID to use
	var loginID uuid.UUID
	var err error

	// If a specific login ID is provided in the request, use it (admin only)
	if req.LoginID != "" {
		// Check if the user has admin privileges
		if !client.IsAdmin(authUser) {
			renderErrorResponse(w, r, http.StatusForbidden, "Permission denied", "Only administrators can link devices to specific logins")
			return
		}

		// Parse the provided login ID
		loginID, err = uuid.Parse(req.LoginID)
		if err != nil {
			slog.Error("Failed to parse login ID", "error", err)
			renderErrorResponse(w, r, http.StatusBadRequest, "Invalid login ID", err.Error())
			return
		}
	} else {
		// Otherwise, use the authenticated user's login ID
		loginID = authUser.LoginID
		if loginID == uuid.Nil {
			slog.Error("Invalid login ID", "loginID", loginID)
			renderErrorResponse(w, r, http.StatusInternalServerError, "Invalid login ID", "Login ID is not valid")
			return
		}
	}

	// Link device to login
	err = h.deviceService.LinkDeviceToLogin(r.Context(), loginID, req.Fingerprint)
	if err != nil {
		slog.Error("Failed to link device to login", "error", err)
		renderErrorResponse(w, r, http.StatusInternalServerError, "Failed to link device to login", err.Error())
		return
	}

	// Get expiry information by calling the repository directly
	// We'll need to modify this if we add GetLoginDeviceWithExpiry to the service
	loginDevice, err := h.deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), req.Fingerprint, loginID)

	if err != nil {
		slog.Error("Failed to get device link", "error", err)
		renderErrorResponse(w, r, http.StatusInternalServerError, "Failed to get device link", err.Error())
		return
	}

	if loginDevice.IsExpired() {
		renderErrorResponse(w, r, http.StatusBadRequest, "Device link expired", "")
		return
	}

	// Return success response
	response := LinkDeviceResponse{
		Status:    "success",
		Message:   "Device linked to login successfully",
		ExpiresAt: loginDevice.ExpiresAt.Format(http.TimeFormat),
	}
	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// GetDeviceStatus handles checking if a device is linked to a login
func (h *DeviceHandler) GetDeviceStatus(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok || authUser == nil {
		renderErrorResponse(w, r, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	// Get fingerprint from URL parameter
	fingerprint := chi.URLParam(r, "fingerprint")
	if fingerprint == "" {
		renderErrorResponse(w, r, http.StatusBadRequest, "Missing required parameter", "fingerprint is required")
		return
	}

	// Check if device is linked to login
	loginID := authUser.LoginID // Using LoginID field directly
	if loginID == uuid.Nil {
		slog.Error("Invalid login ID", "loginID", loginID)
		renderErrorResponse(w, r, http.StatusInternalServerError, "Invalid login ID", "Login ID is not valid")
		return
	}

	isLinked := false

	_, err := h.deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), fingerprint, loginID)
	if err != nil {
		slog.Error("Failed to get device link", "error", err)
	} else {
		isLinked = true
	}

	// Return status
	status := "unknown"
	message := "Device is not linked to login"
	if isLinked {
		status = "trusted"
		message = "Device is linked to login"
	}

	response := SuccessResponse{
		Status:  status,
		Message: message,
	}
	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// GetDevicesByLogin handles fetching devices linked to a specific login
func (h *DeviceHandler) GetDevicesByLogin(w http.ResponseWriter, r *http.Request) {
	// Get login ID from URL parameter
	loginIDStr := chi.URLParam(r, "login_id")
	if loginIDStr == "" {
		renderErrorResponse(w, r, http.StatusBadRequest, "Missing required parameter", "login_id is required")
		return
	}

	// Parse login ID
	loginID, err := uuid.Parse(loginIDStr)
	if err != nil {
		slog.Error("Failed to parse login ID", "error", err)
		renderErrorResponse(w, r, http.StatusBadRequest, "Invalid login ID", err.Error())
		return
	}

	// Get authenticated user from context
	authUser, ok := r.Context().Value(client.AuthUserKey).(*client.AuthUser)
	if !ok || authUser == nil {
		renderErrorResponse(w, r, http.StatusUnauthorized, "Authentication required", "")
		return
	}

	// Check if user has permission to view devices for this login
	// Either the user is an admin or they're viewing their own login's devices
	if !client.IsAdmin(authUser) && authUser.LoginID != loginID {
		renderErrorResponse(w, r, http.StatusForbidden, "Permission denied", "You don't have permission to view devices for this login")
		return
	}

	// Get devices for the login
	devices, err := h.deviceService.FindDevicesByLogin(r.Context(), loginID)
	if err != nil {
		slog.Error("Failed to get devices for login", "error", err)
		renderErrorResponse(w, r, http.StatusInternalServerError, "Failed to get devices for login", err.Error())
		return
	}

	// Convert devices to DeviceWithLogin
	devicesWithLogin := make([]DeviceWithLogin, 0, len(devices))
	for _, d := range devices {
		// Get the login device link to get expiration information
		loginDevice, err := h.deviceService.FindLoginDeviceByFingerprintAndLoginID(r.Context(), d.Fingerprint, loginID)
		if err != nil {
			slog.Error("Failed to get login device link", "fingerprint", d.Fingerprint, "loginID", loginID, "error", err)
			// Continue with other devices even if we can't get link info for this one
			deviceWithLogin := DeviceWithLogin{
				Device: d,
				LinkedLogins: []LoginInfo{
					{
						ID:       loginID.String(),
						Username: "N/A", // We don't have the username here, but we know it's linked to this login
					},
				},
			}
			devicesWithLogin = append(devicesWithLogin, deviceWithLogin)
			continue
		}

		deviceWithLogin := DeviceWithLogin{
			Device: d,
			LinkedLogins: []LoginInfo{
				{
					ID:       loginID.String(),
					Username: "N/A", // We don't have the username here, but we know it's linked to this login
				},
			},
			ExpiresAt: loginDevice.ExpiresAt.Format(http.TimeFormat),
		}
		devicesWithLogin = append(devicesWithLogin, deviceWithLogin)
	}

	// Return success response
	response := ListDevicesResponse{
		Status:  "success",
		Message: "Devices retrieved successfully",
		Devices: devicesWithLogin,
	}
	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// Handler returns a http.Handler for the device API
func Handler(h *DeviceHandler) http.Handler {
	r := chi.NewRouter()

	r.Get("/", h.ListDevices)
	r.Post("/register", h.CreateDevice)
	r.Post("/link", h.LinkDeviceToLogin)
	r.Get("/status/{fingerprint}", h.GetDeviceStatus)
	r.Get("/login/{login_id}", h.GetDevicesByLogin)

	return r
}

// renderErrorResponse renders an error response with the given status code and message
func renderErrorResponse(w http.ResponseWriter, r *http.Request, statusCode int, message, errorDetail string) {
	response := ErrorResponse{
		Status:  "error",
		Message: message,
	}

	if errorDetail != "" {
		response.Error = errorDetail
	}

	render.Status(r, statusCode)
	render.JSON(w, r, response)
}
