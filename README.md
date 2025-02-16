# Simple IDM

A simple Identity Management system with user authentication and authorization capabilities.

## Roadmap

The following features are planned for implementation:

- [ ] Initial password reset functionality
- [ ] Email-based password reset flow
- [ ] Password reset page and API endpoints
- [ ] Password complexity requirements
- [ ] Change password functionality
- [ ] Two-factor authentication using TOTP

## Development Setup

### Prerequisites

#### Install sqlc

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

### Database Setup

#### Create Database

```sql
CREATE Role idm WITH PASSWORD 'pwd';
CREATE DATABASE idm_db ENCODING 'UTF8' OWNER idm;
GRANT ALL PRIVILEGES ON DATABASE idm_db TO idm;
ALTER ROLE idm WITH LOGIN;
```

#### Run Migration

```bash
make migrate-up-idm
```

#### Fix Database Permissions

```sql
ALTER TABLE users OWNER TO idm;
```

### Sample Data Setup

#### Insert Users

```sql
-- crypt pwd -> $2a$10$CFUjSFcMhCoBvnNrpllwuObUkO2TlJ5jnLzdg0tZ0voB1LLujT9c6

INSERT INTO users (username, name, password, email, created_by)
VALUES ('admin', 'admin', convert_to('$2a$10$CFUjSFcMhCoBvnNrpllwuObUkO2TlJ5jnLzdg0tZ0voB1LLujT9c6', 'UTF8'), 'admin@example.com', 'system');

update users set password = convert_to('$2a$10$CFUjSFcMhCoBvnNrpllwuObUkO2TlJ5jnLzdg0tZ0voB1LLujT9c6', 'UTF8') where username = 'admin';

update users set password = '$2a$10$CFUjSFcMhCoBvnNrpllwuObUkO2TlJ5jnLzdg0tZ0voB1LLujT9c6' where username = 'admin';

-- test user
INSERT INTO users (username, name, password, email, created_by)
VALUES ('test', 'test', '$2a$10$Ly3ACkZKafj455GovEcivOxtgD3QMjaq0p16PtMWJNSzUs0il4mrq', 'test@example.com', 'system');

SELECT convert_from(password, 'UTF8') FROM users WHERE username = 'test';
```

#### Insert Roles

```sql
INSERT INTO roles (name, description)
VALUES ('admin', 'Administrator with full access');
```

#### Link Users to Roles

```sql
select * from users;
select * from roles;

INSERT INTO user_roles (user_uuid, role_uuid)
VALUES ((SELECT uuid FROM users WHERE username = 'admin'), (SELECT uuid FROM roles WHERE name = 'admin'));
```

## API Testing Guide

### Basic API Tests

Test the users API endpoint:
```bash
curl -i -X POST localhost:4000/api/users -d '{"email": "test@example.com"}' -H "Content-Type: application/json" 

curl -i localhost:4000/api/users
```

### User Management

#### Create User

```bash
curl -i -X POST localhost:4000/api/v4/user  --data '{"name":"xyz", "email": "abc"}'  --header "Content-Type: application/json"
```

#### Login

```bash
curl -i -X POST localhost:4000/login  --data '{"username":"admin", "password": "pwd"}'  --header "Content-Type: application/json"
```

    