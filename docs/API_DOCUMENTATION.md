# Simple IDM API Documentation

Simple IDM is an Identity Management system that provides user authentication, authorization, and management capabilities. This document outlines the available API endpoints and their usage.

## Quick Start

### In-Memory Mode (No Database)

Test APIs immediately without any setup:

```bash
# Start in-memory server
cd cmd/inmem && go run main.go

# Login with pre-seeded credentials
curl -X POST http://localhost:4000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@example.com","password":"password123"}'

# Use token for authenticated requests
TOKEN="<access_token from response>"
curl http://localhost:4000/api/idm/users \
  -H "Authorization: Bearer $TOKEN"
```

### Generate Test Tokens

Generate JWT tokens without running a server:

```bash
# Basic token
go run cmd/tokengen/main.go

# Token with custom claims
go run cmd/tokengen/main.go \
  -secret "your-jwt-secret" \
  -claims '{"user_uuid":"test-uuid","roles":["admin"]}'
```

See [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) for comprehensive local development options.

## Base URL

The API server runs on port 4000 by default: `http://localhost:4000`

## API Organization

The APIs are organized into different packages with specific prefixes:
- Authentication: `/api/idm/auth` or `/api/v2/auth` (in-memory)
- Profile Management: `/api/idm/profile`
- Device Management: `/api/idm/device`
- Two-Factor Authentication: `/idm/2fa`
- User Management: `/idm/users` or `/api/idm/users` (in-memory)
- Role Management: `/idm/roles` or `/api/idm/roles` (in-memory)
- Login Management: `/api/idm/logins`
- Signup: `/api/idm/signup` or `/api/v2/auth/signup` (in-memory)
- Health Check: `/health`

### In-Memory Service Endpoints

The in-memory service (`cmd/inmem`) provides a subset of endpoints for testing:

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v2/auth/login` | No | Login with username/password |
| POST | `/api/v2/auth/logout` | No | Logout |
| POST | `/api/v2/auth/refresh` | No | Refresh access token |
| POST | `/api/v2/auth/signup` | No | Register new user |
| GET | `/api/idm/users` | Yes | List all users |
| GET | `/api/idm/roles` | Yes | List all roles |
| GET | `/health` | No | Health check |

## Login

### 1. Username/Password Login
- **Endpoint**: `/api/idm/auth/login`
- **Method**: POST
- **Description**: Authenticate using username or email
- **Request Body**:
  ```json
  {
    "username": "string",  // Can be username or email
    "password": "string"
  }
  ```
- **Response Scenarios**:
  1. Success (200):
     ```json
     {
       "status": "success",
       "message": "Login successful",
       "user": {
         "id": "string",
         "name": "string",
         "email": "string",
         "role": "string"
       }
     }
     ```
  2. Multiple Users (202):
     ```json
     {
       "status": "multiple_users",
       "message": "Multiple users found, please select one",
       "temp_token": "string",
       "users": [
         {
           "id": "string",
           "name": "string",
           "email": "string",
           "role": "string"
         }
       ]
     }
     ```
  3. 2FA Required (202):
     ```json
     {
       "status": "2fa_required",
       "message": "Two-factor authentication is required",
       "temp_token": "string",
       "two_factor_methods": [
         {
           "type": "string",
           "id": "string"
         }
       ]
     }
     ```

### 2. Email Login
- **Endpoint**: `/api/idm/auth/login/email`
- **Method**: POST
- **Description**: Login using email address
- **Request Body**:
  ```json
  {
    "email": "string",
    "password": "string"
  }
  ```
- **Response**: Same as username/password login responses

### 3. Magic Link Login
- **Endpoint**: `/api/idm/auth/login/magic-link`
- **Method**: POST
- **Description**: Request a magic link for passwordless login
- **Request Body**:
  ```json
  {
    "username": "string"  // Can be username or email
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "message": "If an account exists with that username, we will send a login link to the associated email."
  }
  ```

#### Magic Link with Email
- **Endpoint**: `/api/idm/auth/login/magic-link/email`
- **Method**: POST
- **Description**: Request a magic link using email address
- **Request Body**:
  ```json
  {
    "email": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "message": "If an account exists with that email, we will send a login link."
  }
  ```

#### Magic Link Validation
- **Endpoint**: `/api/idm/auth/login/magic-link/validate`
- **Method**: GET
- **Parameters**: 
  - `token`: The magic link token (query parameter)
- **Response**: Same as username/password login responses

## Two-Factor Authentication (2FA) During Login

### Send 2FA Code
- **Endpoint**: `/api/idm/auth/2fa/send`
- **Method**: POST
- **Description**: Send a 2FA code to the user
- **Authentication**: Temporary token required
- **Request Body**:
  ```json
  {
    "twofa_id": "uuid",
    "twofa_type": "string",
    "temp_token": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "status": "success",
    "message": "2FA code sent successfully"
  }
  ```

### Validate 2FA Code
- **Endpoint**: `/api/idm/auth/2fa/validate`
- **Method**: POST
- **Description**: Validate a 2FA code
- **Authentication**: Temporary token required
- **Request Body**:
  ```json
  {
    "twofa_id": "uuid",
    "twofa_type": "string",
    "code": "string",
    "temp_token": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "status": "success",
    "message": "2FA validation successful",
    "access_token": "string",
    "refresh_token": "string"
  }
  ```

## User Selection During Login
### Get Available Users
- **Endpoint**: `/api/idm/auth/users`
- **Method**: GET
- **Description**: Get list of users available for the current login
- **Authentication**: Temporary token required
- **Parameters**: 
  - `temp_token`: Temporary token from previous step (query parameter)
- **Response**: 200 OK
  ```json
  {
    "users": [
      {
        "id": "string",
        "name": "string",
        "email": "string",
        "role": "string"
      }
    ]
  }
  ```

### Select User During Login
- **Endpoint**: `/api/idm/auth/user/switch`
- **Method**: POST
- **Description**: Select a specific user during the login flow when multiple users are found
- **Authentication**: Temporary token required
- **Request Body**:
  ```json
  {
    "user_id": "string",
    "temp_token": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "status": "success",
    "message": "User selected successfully",
    "access_token": "string",
    "refresh_token": "string"
  }
  ```


## Password Reset

#### Get Password Reset Policy
- **Endpoint**: `/api/idm/auth/password/reset/policy`
- **Method**: GET
- **Description**: Get password reset policy settings
- **Response**: 200 OK
  ```json
  {
    "min_length": 8,
    "require_digit": true,
    "require_lowercase": true,
    "require_uppercase": true,
    "require_special_char": true,
    "disallow_common_pwds": true,
    "max_repeated_chars": 3,
    "history_check_count": 3,
    "expiration_days": 90
  }
  ```

#### Initialize Password Reset
- **Endpoint**: `/api/idm/auth/password/reset/init`
- **Method**: POST
- **Description**: Initialize password reset process
- **Request Body**:
  ```json
  {
    "username": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "message": "If an account exists with that username, we will send a password reset link."
  }
  ```

#### Initialize Password Reset with Email
- **Endpoint**: `/api/idm/auth/password/reset/init/email`
- **Method**: POST
- **Description**: Initialize password reset process using email
- **Request Body**:
  ```json
  {
    "email": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "message": "If an account exists with that email, we will send a password reset link."
  }
  ```



## Profile Management 2FA (User Personal Setting)

### Get 2FA Methods
- **Endpoint**: `/api/idm/profile/2fa`
- **Method**: GET
- **Description**: Get all 2FA methods for the current user
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "count": 1,
    "methods": [
      {
        "two_factor_id": "uuid",
        "type": "string",
        "enabled": true
      }
    ]
  }
  ```

### Setup 2FA Method
- **Endpoint**: `/api/idm/profile/2fa/setup`
- **Method**: POST
- **Description**: Setup a new 2FA method for the current user
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "twofa_type": "string"
  }
  ```
- **Response**: 201 Created
  ```json
  {
    "result": "success"
  }
  ```

### Enable 2FA
- **Endpoint**: `/api/idm/profile/2fa/enable`
- **Method**: POST
- **Description**: Enable an existing 2FA method
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "twofa_type": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "result": "success"
  }
  ```

### Disable 2FA
- **Endpoint**: `/api/idm/profile/2fa/disable`
- **Method**: POST
- **Description**: Disable an existing 2FA method
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "twofa_type": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "result": "success"
  }
  ```

## Login Management 2FA (Admin Operations)

### Get Login's 2FA Methods
- **Endpoint**: `/api/idm/logins/{login_id}/2fa`
- **Method**: GET
- **Description**: Get all 2FA methods for a specific login
- **Authentication**: Required (Admin)
- **Response**: 200 OK
  ```json
  {
    "count": 1,
    "methods": [
      {
        "type": "string",
        "enabled": true,
        "two_factor_id": "uuid"
      }
    ]
  }
  ```

### Enable 2FA for Login
- **Endpoint**: `/api/idm/logins/{login_id}/2fa/enable`
- **Method**: POST
- **Description**: Enable 2FA for a specific login
- **Authentication**: Required (Admin)
- **Response**: 200 OK
  ```json
  {
    "secret": "string",
    "qr_code": "string"
  }
  ```

### Disable 2FA for Login
- **Endpoint**: `/api/idm/logins/{login_id}/2fa/disable`
- **Method**: POST
- **Description**: Disable 2FA for a specific login
- **Authentication**: Required (Admin)
- **Request Body**:
  ```json
  {
    "code": "string"
  }
  ```
- **Response**: 200 OK


## User Management

### List Users
- **Endpoint**: `/idm/users`
- **Method**: GET
- **Description**: Retrieve a list of all users
- **Authentication**: Required
- **Response**: Array of user objects

### Create User
- **Endpoint**: `/idm/users`
- **Method**: POST
- **Description**: Create a new user
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "name": "string",
    "email": "string"
  }
  ```
- **Response**: Created user object

## Role Management

The system includes role-based access control with the following endpoints:

### Get Roles
- **Endpoint**: `/idm/roles`
- **Method**: GET
- **Description**: Retrieve available roles
- **Authentication**: Required
- **Response**: Array of role objects

### Assign Role
- **Endpoint**: `/idm/roles/assign`
- **Method**: POST
- **Description**: Assign a role to a user
- **Authentication**: Required (Admin only)
- **Request Body**:
  ```json
  {
    "user_id": "string",
    "role_id": "string"
  }
  ```

## Profile Management

### Password Management

#### Get Password Policy
- **Endpoint**: `/api/idm/profile/password/policy`
- **Method**: GET
- **Description**: Get password policy settings
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "min_length": 8,
    "require_digit": true,
    "require_lowercase": true,
    "require_uppercase": true,
    "require_special_char": true,
    "disallow_common_pwds": true,
    "max_repeated_chars": 3,
    "history_check_count": 3,
    "expiration_days": 90
  }
  ```

#### Change Password
- **Endpoint**: `/api/idm/profile/password`
- **Method**: PUT
- **Description**: Change user's password
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "current_password": "string",
    "new_password": "string"
  }
  ```

#### Change Username
- **Endpoint**: `/api/idm/profile/username`
- **Method**: PUT
- **Description**: Change username
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "new_username": "string"
  }
  ```

### Phone Management

#### Get Phone Number
- **Endpoint**: `/api/idm/profile/phone`
- **Method**: GET
- **Description**: Get user's phone number
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "phone": "string"
  }
  ```

#### Update Phone Number
- **Endpoint**: `/api/idm/profile/phone`
- **Method**: PUT
- **Description**: Update user's phone number
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "phone": "string"
  }
  ```

#### Send Phone Verification
- **Endpoint**: `/api/idm/profile/phone/verify/send`
- **Method**: POST
- **Description**: Send verification code to phone number
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "phone": "string"
  }
  ```

#### Verify Phone Number
- **Endpoint**: `/api/idm/profile/phone/verify`
- **Method**: POST
- **Description**: Verify phone number with code
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "phone": "string",
    "code": "string"
  }
  ```

### Device Management

#### Get My Devices
- **Endpoint**: `/api/idm/profile/devices`
- **Method**: GET
- **Description**: Get list of user's devices
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "status": "success",
    "message": "string",
    "devices": [
      {
        "fingerprint": "string",
        "user_agent": "string",
        "device_name": "string",
        "device_type": "string",
        "display_name": "string",
        "last_login_at": "string",
        "created_at": "string",
        "expires_at": "string",
        "linked_logins": [
          {
            "id": "string",
            "username": "string"
          }
        ]
      }
    ]
  }
  ```

#### Update Device Display Name
- **Endpoint**: `/api/idm/profile/devices/{fingerprint}/display-name`
- **Method**: PUT
- **Description**: Update device display name
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "display_name": "string"
  }
  ```

#### Unlink Device
- **Endpoint**: `/api/idm/profile/devices/unlink`
- **Method**: POST
- **Description**: Unlink device from login
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "fingerprint": "string"
  }
  ```

### User Association

#### Find Users with Login
- **Endpoint**: `/api/idm/profile/users`
- **Method**: GET
- **Description**: Find users associated with the current login
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  [
    {
      "id": "string",
      "name": "string",
      "email": "string",
      "role": "string"
    }
  ]
  ```

#### Associate User
- **Endpoint**: `/api/idm/profile/login/associate`
- **Method**: POST
- **Description**: Associate a login with the current user
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```

#### Complete User Association
- **Endpoint**: `/api/idm/profile/users/associate`
- **Method**: POST
- **Description**: Complete user association when multiple users are available
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "login_id": "string",
    "selected_users": [
      {
        "user_id": "string",
        "display_name": "string",
        "email": "string"
      }
    ]
  }
  ```

#### Switch User
- **Endpoint**: `/api/idm/profile/user/switch`
- **Method**: POST
- **Description**: Switch to a different user when multiple users are available
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "user_id": "string"
  }
  ```
- **Response**: 200 OK
  ```json
  {
    "status": "success",
    "message": "Successfully switched user",
    "users": [
      {
        "id": "string",
        "name": "string",
        "email": "string",
        "role": "string"
      }
    ]
  }
  ```

## Device Management

### Get Device Expiration
- **Endpoint**: `/api/idm/device/expiration`
- **Method**: GET
- **Description**: Get the device remember-me expiration period
- **Response**:
  ```json
  {
    "expiration_days": 30,
    "message": "Remember this device for 30 days."
  }
  ```

## Response Status Codes

The API uses standard HTTP status codes:
- 200: Success
- 201: Created
- 202: Accepted (requires additional action)
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 429: Too Many Requests
- 500: Internal Server Error

## Special Response Status Values

The API uses special status values in responses to indicate different scenarios:
- `success`: Operation completed successfully
- `multiple_users`: Multiple users found, selection required
- `user_association_required`: User association needed
- `user_association_selection_required`: Multiple users available for association
- `2fa_required`: Two-factor authentication required

## Error Responses

Error responses include a message field explaining the error:
```json
{
  "error": "Error message description"
}
```

## Security Features

1. Multiple Authentication Methods:
   - Username/password login
   - Email-based login
   - Magic link (passwordless) authentication
2. Two-Factor Authentication (2FA):
   - Multiple 2FA methods support
   - Enable/disable/manage 2FA methods
3. Device Security:
   - Device fingerprinting
   - Remember-me functionality
   - Configurable device expiration
4. Session Management:
   - JWT-based authentication
   - Access and refresh tokens
   - Temporary tokens for multi-step operations
5. User Association:
   - Support for multiple user accounts
   - Secure user selection process
6. Access Control:
   - Role-based access control (RBAC)
   - Fine-grained permissions
7. Security Headers:
   - CORS configuration
   - Content Security Policy
8. Audit Trail:
   - Login attempt tracking
   - IP address logging
   - User agent tracking

## Cookie Management

The API uses secure cookies for token management:
- `access_token`: Short-lived token for API access
- `refresh_token`: Long-lived token for obtaining new access tokens
- `temp_token`: Temporary token for multi-step operations (2FA, user selection)
- `logout_token`: Used during logout process

## Testing Examples

```bash
# Username/Password Login
curl -i -X POST localhost:4000/api/idm/auth/login \
    --header "Content-Type: application/json" \
    --data '{
        "username": "admin",
        "password": "pwd"
    }'

# Login with Email
curl -i -X POST localhost:4000/api/idm/auth/login/email \
    --header "Content-Type: application/json" \
    --data '{
        "email": "user@example.com",
        "password": "pwd"
    }'

# Request Magic Link
curl -i -X POST localhost:4000/api/idm/auth/login/magic-link \
    --header "Content-Type: application/json" \
    --data '{
        "username": "user@example.com"
    }'

# Request Magic Link with Email
curl -i -X POST localhost:4000/api/idm/auth/login/magic-link/email \
    --header "Content-Type: application/json" \
    --data '{
        "email": "user@example.com"
    }'

# Initialize Password Reset
curl -i -X POST localhost:4000/api/idm/auth/password/reset/init \
    --header "Content-Type: application/json" \
    --data '{
        "username": "user123"
    }'

# Initialize Password Reset with Email
curl -i -X POST localhost:4000/api/idm/auth/password/reset/init/email \
    --header "Content-Type: application/json" \
    --data '{
        "email": "user@example.com"
    }'

# Get Password Reset Policy
curl -i localhost:4000/api/idm/auth/password/reset/policy

# Send 2FA Code
curl -i -X POST localhost:4000/api/idm/auth/2fa/send \
    --header "Content-Type: application/json" \
    --data '{
        "twofa_id": "123e4567-e89b-12d3-a456-426614174000",
        "twofa_type": "totp",
        "temp_token": "YOUR_TEMP_TOKEN"
    }'

# Validate 2FA Code
curl -i -X POST localhost:4000/api/idm/auth/2fa/validate \
    --header "Content-Type: application/json" \
    --data '{
        "twofa_id": "123e4567-e89b-12d3-a456-426614174000",
        "twofa_type": "totp",
        "code": "123456",
        "temp_token": "YOUR_TEMP_TOKEN"
    }'

# Get Available Users
curl -i "localhost:4000/api/idm/auth/users?temp_token=YOUR_TEMP_TOKEN"

# Switch User During Login
curl -i -X POST localhost:4000/api/idm/auth/user/switch \
    --header "Content-Type: application/json" \
    --data '{
        "user_id": "123e4567-e89b-12d3-a456-426614174000",
        "temp_token": "YOUR_TEMP_TOKEN"
    }'

# Get 2FA Methods
curl -i localhost:4000/api/idm/profile/2fa \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Setup 2FA
curl -i -X POST localhost:4000/api/idm/profile/2fa/setup \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN" \
    --data '{
        "twofa_type": "totp"
    }'

# Enable 2FA
curl -i -X POST localhost:4000/api/idm/profile/2fa/enable \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN" \
    --data '{
        "twofa_type": "totp"
    }'

# Admin: Get Login's 2FA Methods
curl -i localhost:4000/api/idm/logins/123e4567-e89b-12d3-a456-426614174000/2fa \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Admin: Enable 2FA for Login
curl -i -X POST localhost:4000/api/idm/logins/123e4567-e89b-12d3-a456-426614174000/2fa/enable \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Admin: Generate Backup Codes
curl -i -X POST localhost:4000/api/idm/logins/123e4567-e89b-12d3-a456-426614174000/2fa/backup-codes \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Get Password Policy
curl -i localhost:4000/api/idm/profile/password/policy \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Change Password
curl -i -X PUT localhost:4000/api/idm/profile/password \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN" \
    --data '{
        "current_password": "old_password",
        "new_password": "new_password"
    }'

# Get Phone Number
curl -i localhost:4000/api/idm/profile/phone \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Send Phone Verification
curl -i -X POST localhost:4000/api/idm/profile/phone/verify/send \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN" \
    --data '{
        "phone": "+1234567890"
    }'

# Get My Devices
curl -i localhost:4000/api/idm/profile/devices \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Update Device Display Name
curl -i -X PUT localhost:4000/api/idm/profile/devices/device123/display-name \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN" \
    --data '{
        "display_name": "My Work Laptop"
    }'

# Find Users with Login
curl -i localhost:4000/api/idm/profile/users \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Switch User
curl -i -X POST localhost:4000/api/idm/profile/user/switch \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer YOUR_JWT_TOKEN" \
    --data '{
        "user_id": "123e4567-e89b-12d3-a456-426614174000"
    }'

# Get Device Expiration
curl -i localhost:4000/api/idm/device/expiration

# List Users (Admin only)
curl -i localhost:4000/idm/users \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"

# Get User Profile
curl -i localhost:4000/api/idm/profile \
    --header "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Database Schema

The API interacts with the following main database tables:
- users: Stores user information
- login: Stores login credentials and 2FA settings
- roles: Defines available roles
- user_roles: Maps users to roles
- devices: Stores device fingerprints and expiration
- login_attempts: Tracks login attempts and security events

For detailed database setup and sample data, refer to the project README.

## Rate Limiting

The API implements rate limiting for security-sensitive endpoints:
- Login attempts
- Magic link requests
- 2FA validation attempts

