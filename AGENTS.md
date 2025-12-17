# Claude Code Agents Guide

Guide for using Claude Code agents effectively with the Simple IDM project.

## Quick Reference

### Common Tasks

```bash
# Start Claude Code in this project
claude

# Run with specific task
claude "add a new API endpoint for user search"

# Continue previous conversation
claude --continue
```

### Pre-approved Commands

The following commands are auto-approved (no confirmation needed):

```bash
Bash(find:*)        # File discovery
Bash(go build:*)    # Build project
Bash(go test:*)     # Run tests
Bash(wc:*)          # Count lines
```

## Effective Prompts

### Code Generation

```
# Add new endpoint
"Add a GET endpoint /api/idm/users/search that searches users by name or email"

# Add new service method
"Add a method to LoginService that checks if a user's password has expired"

# Add database query
"Add a sqlc query to find all users created in the last 30 days"
```

### Code Exploration

```
# Understand architecture
"Explain how the login flow works from request to response"

# Find implementations
"Where is device fingerprinting handled?"

# Trace dependencies
"What services does the signup handler depend on?"
```

### Testing

```
# Run specific tests
"Run tests for the login package"

# Add test coverage
"Add unit tests for the TwoFaService.ValidateCode method"

# Integration testing
"Test the magic link flow end-to-end"
```

### Refactoring

```
# Extract interface
"Extract a repository interface from the ProfileService"

# Rename across codebase
"Rename GetUserByID to FindUserByID across all packages"

# Add new config option
"Add a configurable rate limit for login attempts"
```

## Project-Specific Patterns

### Adding a New API Endpoint

1. **Define in OpenAPI spec**: `pkg/<package>/api/<package>.yaml`
2. **Generate code**: `cd pkg/<package>/api && ./gen-<package>.sh`
3. **Implement handler**: `pkg/<package>/api/handle.go`
4. **Wire routes**: `cmd/loginv2/main.go`

Example prompt:
```
"Add a new endpoint POST /api/idm/profile/avatar that accepts an image upload.
Follow the existing OpenAPI patterns in the profile package."
```

### Adding a Database Query

1. **Add SQL**: `pkg/<package>/<package>db/query.sql`
2. **Generate**: `cd pkg/<package> && sqlc generate`
3. **Use in service**: `pkg/<package>/service.go`

Example prompt:
```
"Add a query to find all logins that haven't been used in 90 days.
Add it to the logins package following existing patterns."
```

### Adding a New Config Option

1. **Add to config struct**: `pkg/config/` or service config
2. **Add env variable**: `cmd/loginv2/.env.example`
3. **Document**: Update CLAUDE.md

Example prompt:
```
"Add a configurable session timeout. Use the existing config patterns
in pkg/config/ with a NewXxxConfigFromEnv() factory function."
```

### Adding a Login Flow Step

1. **Create step**: `pkg/loginflow/<step>_step.go`
2. **Implement interface**: `LoginFlowStep`
3. **Register in flow**: Set appropriate order priority

Example prompt:
```
"Add a login flow step that checks if the user's account is suspended.
It should run after credential validation (order 100) but before 2FA (order 500)."
```

## Custom Slash Commands

Create custom commands in `.claude/commands/`:

### Example: `/test-login`

Create `.claude/commands/test-login.md`:
```markdown
Run login tests and report any failures:

1. Run: go test -v ./pkg/login/...
2. Run: go test -v ./pkg/loginflow/...
3. Summarize any failures with file:line references
```

### Example: `/add-endpoint`

Create `.claude/commands/add-endpoint.md`:
```markdown
Add a new API endpoint. User will provide:
- Package name
- HTTP method and path
- Request/response types

Steps:
1. Update OpenAPI spec in pkg/{package}/api/{package}.yaml
2. Run code generation
3. Implement handler in pkg/{package}/api/handle.go
4. Add route in cmd/loginv2/main.go if needed
5. Add tests
```

### Example: `/db-query`

Create `.claude/commands/db-query.md`:
```markdown
Add a new database query. User will provide:
- Package name
- Query description

Steps:
1. Add SQL to pkg/{package}/{package}db/query.sql
2. Run sqlc generate
3. Update service to use new query
4. Add test for the new functionality
```

## Working with Key Areas

### Authentication Flow

Key files:
- `pkg/loginflow/` - Flow orchestration
- `pkg/login/` - Credential handling
- `pkg/twofa/` - 2FA logic
- `pkg/device/` - Device recognition

```
"Trace the authentication flow for a user with 2FA enabled"
```

### User Management

Key files:
- `pkg/iam/` - User CRUD operations
- `pkg/profile/` - Profile management
- `pkg/signup/` - Registration

```
"Add ability to bulk import users from CSV"
```

### OAuth2/OIDC

Key files:
- `pkg/oidc/` - OIDC provider
- `pkg/oauth2client/` - Client management
- `pkg/externalprovider/` - External OAuth

```
"Add support for Apple Sign In as an external provider"
```

## Testing Workflows

### Unit Tests

```
"Run tests for login package with coverage"
# Claude runs: go test -v -cover ./pkg/login/...
```

### Integration Tests

```
"Start the in-memory server and test the login flow"
# Claude runs: cd cmd/inmem && go run main.go
# Then tests with curl commands
```

### Generate Test Token

```
"Generate a test JWT token for user ID abc-123 with admin role"
# Claude runs: go run cmd/tokengen/main.go -claims '{"user_uuid":"abc-123","roles":["admin"]}'
```

## Code Generation Tasks

### After Modifying SQL Queries

```
"Regenerate sqlc code for the login package"
# Claude runs: cd pkg/login && sqlc generate
```

### After Modifying OpenAPI Spec

```
"Regenerate API handlers for the profile package"
# Claude runs: cd pkg/profile/api && ./gen-profile.sh
```

## Debugging Assistance

### Trace an Error

```
"I'm getting 'invalid token' errors during login. Trace where token
validation happens and what could cause this error."
```

### Find Configuration Issues

```
"The magic link emails aren't being sent. Check the notification
configuration and email service setup."
```

### Database Issues

```
"Users are getting 'duplicate key' errors on signup. Find where
email uniqueness is enforced and check the constraints."
```

## Best Practices

### Be Specific About Patterns

```
# Good - references existing patterns
"Add a file-based repository for the new audit package, following
the pattern in pkg/login/file_repository.go"

# Less effective - no context
"Add file storage for audits"
```

### Include Context for Changes

```
# Good - explains the goal
"Add rate limiting to the password reset endpoint to prevent abuse.
Limit to 3 requests per email per hour."

# Less effective - just the action
"Add rate limiting"
```

### Reference Existing Code

```
# Good - points to examples
"Add a new config type for audit settings, similar to LoginConfig
in pkg/config/login_config.go"

# Less effective - no reference
"Add audit configuration"
```

## Multi-Step Tasks

For complex tasks, break them down:

```
"I want to add audit logging. Let's plan this:
1. First, explore existing logging patterns in the codebase
2. Then design the audit log schema
3. Create the audit package with repository
4. Integrate with key operations (login, user changes, etc.)"
```

## Getting Help

```
# Understanding the codebase
"Give me an overview of the authentication architecture"

# Finding specific code
"Where is the JWT token generation implemented?"

# Understanding patterns
"Explain the repository pattern used in this project"
```

## Environment Setup

### For Development

```bash
# In-memory mode (no database)
cd cmd/inmem && go run main.go

# With PostgreSQL
cd cmd/loginv2 && go run main.go
```

### For Testing

```bash
# Generate test tokens
go run cmd/tokengen/main.go -secret "test-secret"

# Run all tests
go test -v ./...
```

## See Also

- [CLAUDE.md](CLAUDE.md) - Project guidance for Claude Code
- [docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md) - Local development options
- [docs/API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) - API reference
