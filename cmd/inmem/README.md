# In-Memory IDM Service

Zero-setup Identity Management service for local development and testing. No database required - all data stored in memory.

## Quick Start

```bash
go run main.go
```

Server starts at `http://localhost:4000`

## Pre-seeded Data

| Type | Value |
|------|-------|
| **Admin Email** | `admin@example.com` |
| **Admin Password** | `password123` |
| **Roles** | `admin`, `user` |

## API Endpoints

### Public (No Auth Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v2/auth/login` | Login with username/password |
| POST | `/api/v2/auth/logout` | Logout |
| POST | `/api/v2/auth/refresh` | Refresh access token |
| POST | `/api/v2/auth/signup` | Register new user |
| GET | `/health` | Health check |

### Protected (Auth Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/idm/users` | List all users |
| GET | `/api/idm/roles` | List all roles |

## Usage Examples

### Login

```bash
curl -X POST http://localhost:4000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@example.com","password":"password123"}'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer"
}
```

### Authenticated Request

```bash
TOKEN="<access_token from login>"

# List users
curl http://localhost:4000/api/idm/users \
  -H "Authorization: Bearer $TOKEN"

# List roles
curl http://localhost:4000/api/idm/roles \
  -H "Authorization: Bearer $TOKEN"
```

### One-liner

```bash
# Get token and use it
TOKEN=$(curl -s -X POST http://localhost:4000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@example.com","password":"password123"}' | jq -r '.access_token')

curl -H "Authorization: Bearer $TOKEN" http://localhost:4000/api/idm/users
```

## Use Cases

- **Quick API testing** - Test IDM APIs without database setup
- **Integration tests** - Spin up for automated testing
- **Demo/prototypes** - Show IDM functionality quickly
- **Learning** - Explore the API without infrastructure

## Configuration

The service uses sensible defaults. No configuration required.

| Setting | Value |
|---------|-------|
| Port | 4000 |
| JWT Secret | `inmem-dev-secret-change-in-production` |
| JWT Algorithm | HS256 |
| Base URL | `http://localhost:4000` |

## Limitations

- **Data not persisted** - All data lost when server stops
- **Single instance** - No clustering support
- **Development only** - Not for production use

## Comparison with Other Services

| Service | Database | Features | Use Case |
|---------|----------|----------|----------|
| `cmd/inmem` | None | Basic auth, users, roles | Quick testing |
| `cmd/quick` | PostgreSQL | OIDC, magic link, RSA keys | Simplified production |
| `cmd/loginv2` | PostgreSQL | Full features (2FA, external providers, etc.) | Production |

## See Also

- [Local Development Guide](../../docs/LOCAL_DEVELOPMENT.md) - Comprehensive local dev options
- [Token Generator](../tokengen/README.md) - Generate test JWT tokens
- [Quick Service](../quick/README.md) - Simplified production service
