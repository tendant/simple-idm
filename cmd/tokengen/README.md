# Token Generator Tool

This command-line tool generates JWT tokens for testing purposes in the Simple-IDM application.

## Usage

```bash
go run cmd/tokengen/main.go [options]
```

### Options

- `-secret string`: Secret key for signing the token (default "your-secret-key")
- `-issuer string`: Issuer of the token (default "simple-idm")
- `-audience string`: Audience of the token (default "public")
- `-subject string`: Subject of the token, usually user ID (default "test-subject")
- `-expiry duration`: Token expiry duration (default 30m)
- `-claims string`: Extra claims in JSON format (default "{}")
- `-format string`: Output format: compact, full, or debug (default "compact")

### Examples

Generate a basic token with default settings:
```bash
go run cmd/tokengen/main.go
```

Generate a token with custom settings:
```bash
go run cmd/tokengen/main.go -secret "my-secret" -subject "user123" -expiry 1h -format debug
```

Generate a token with custom claims:
```bash
go run cmd/tokengen/main.go -claims '{"user_id": "123", "role": "admin", "permissions": ["read", "write"]}'
```

## Output Formats

- `compact`: Just the token string (useful for piping to other commands)
- `full`: Token string and expiry time
- `debug`: Detailed information including token header and claims
