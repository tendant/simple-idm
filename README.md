# Simple IDM

A simple Identity Management system with user authentication and authorization capabilities. This system provides basic user management, authentication, and role-based access control.

## Getting Started

### Running the Application

```bash
# Build and run the application
make build
make run
```

The application will start on port 4000 by default.

## Roadmap

The following features are planned for implementation:

- [X] Migrate to login 
- [ ] Initial password reset functionality
- [ ] Email-based password reset flow
- [ ] Password reset page and API endpoints
- [ ] Password complexity requirements
- [ ] Change password functionality
- [ ] Two-factor authentication using TOTP

## Development Setup

### Prerequisites

- Go 1.21 or later
- PostgreSQL 14 or later
- Make

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
make migrate-up
```

#### Fix Database Permissions

```sql
ALTER TABLE users OWNER TO idm;
```

### Sample Data Setup

#### Insert Users

The following commands will create two users:
- Admin user (username: `admin`, password: `pwd`)
- Test user (username: `test`, password: `test`)

```sql
-- Create login record and store its UUID
WITH new_login AS (
    INSERT INTO login (username, password, created_at)
    VALUES (
        'admin',
        '$2a$10$CFUjSFcMhCoBvnNrpllwuObUkO2TlJ5jnLzdg0tZ0voB1LLujT9c6',  -- hashed value of 'pwd'
        NOW()
    )
    RETURNING id
)
-- Create admin user with the login ID
INSERT INTO users (username, name, email, created_by, login_id)
VALUES (
    'admin',
    'admin',
    'admin@example.com',
    'system',
    (SELECT id FROM login where username = 'admin')
);

-- Create test user
INSERT INTO users (username, name, password, email, created_by)
VALUES (
    'test',
    'test',
    '$2a$10$Ly3ACkZKafj455GovEcivOxtgD3QMjaq0p16PtMWJNSzUs0il4mrq',  -- hashed value of 'test'
    'test@example.com',
    'system'
);
```

#### Insert Roles

```sql
INSERT INTO roles (name, description)
VALUES ('admin', 'Administrator with full access');
```

#### Link Users to Roles

```sql
-- Check available users and roles
SELECT * FROM users;
SELECT * FROM roles;

INSERT INTO user_roles (user_id, role_id)
VALUES ((SELECT id FROM users WHERE username = 'admin'), (SELECT id FROM roles WHERE name = 'admin'));
```

## API Testing Guide

All API endpoints are available on port 4000 by default. Make sure the application is running before testing the APIs.

### User Management

#### List Users
```bash
curl -i localhost:4000/api/users
```

#### Create User
```bash
curl -i -X POST localhost:4000/api/v4/user \
    --header "Content-Type: application/json" \
    --data '{
        "name": "xyz",
        "email": "abc@example.com"
    }'
```

#### Login
```bash
# Login as admin
curl -i -X POST localhost:4000/login \
    --header "Content-Type: application/json" \
    --data '{
        "username": "admin",
        "password": "pwd"
    }'

# Login as test user
curl -i -X POST localhost:4000/login \
    --header "Content-Type: application/json" \
    --data '{
        "username": "test",
        "password": "test"
    }'
```

    