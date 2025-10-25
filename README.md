# Simple IDM

A simple Identity Management system with user authentication and authorization capabilities. This system provides basic user management, authentication, and role-based access control.

## Quick Start Options

### Option 1: Docker Compose (Recommended for Quick Setup)

```bash
# Start the application server
docker-compose up --build 
```

The application will be available at:
- Backend API: http://localhost:4000
- Frontend: http://localhost:3000

Clean up - Remove all volumes created by your Compose project:
```bash
docker-compose down -v
```

### Option 2: Manual Setup (Recommended for Development)

Follow the detailed setup instructions below for more control over your development environment.

## Manual Setup Guide

### Prerequisites

- Go 1.21 or later
- PostgreSQL 14 or later
- Node.js and npm
- Make

### 1. Backend Server Setup

#### Navigate to the backend directory
```bash
cd cmd/loginv2
```

#### Setup Environment Configuration
Copy the example environment file and configure it:
```bash
cp .env.example .env
```

Edit the `.env` file with your configuration. Key variables to update:
- `IDM_PG_PASSWORD`: Your PostgreSQL password
- `JWT_SECRET`: A strong, random secret for JWT tokens
- `EMAIL_*`: Email server configuration for notifications
- `BASE_URL`: Your application's base URL (default: http://localhost:4000)

#### Start the Backend Server
```bash
go run main.go
```

**⚠️ IMPORTANT - First Time Setup:**
If the IDM server currently does not have any users, starting the server will automatically create the first admin user and display the credentials in the console. **This information only appears once, so please save it immediately.**

The console output will look like this:
```
🔐 ADMIN USER CREATED SUCCESSFULLY
Username:     super
Email:        super@example.com
Password:     SOME_PASSWORD
User ID:      929ec4bb-4183-45c9-993b-db59f3913e79
Login ID:     8be02f9c-58e2-4430-a232-063f6265ddce
Admin Role:   20a09c0a-e776-4e99-9541-4fb755252ac0
⚠️  IMPORTANT SECURITY NOTICE:
   • Store this password securely
   • Change the password after first login
   • This password will not be displayed again
```

The backend API will be available at http://localhost:4000

### 2. Frontend Setup

#### Navigate to the frontend directory
```bash
cd frontend
```

#### Install Dependencies
If you don't have npm installed, install Node.js first, then:
```bash
npm install
```

#### Start the Frontend Development Server
```bash
npm run dev
```

The frontend will be available at http://localhost:3000

### 3. Database Setup

#### Create Database and User

```sql
CREATE ROLE idm WITH PASSWORD 'pwd';
CREATE DATABASE idm_db ENCODING 'UTF8' OWNER idm;
GRANT ALL PRIVILEGES ON DATABASE idm_db TO idm;
ALTER ROLE idm WITH LOGIN;
```

#### Run Database Migrations

```bash
make migrate-up
make dump-idm
```

#### Fix Database Permissions

```sql
ALTER TABLE users OWNER TO idm;
```

#### Connect to Database
```bash
psql -h localhost -U idm -d idm_db
```
Password: pwd

### 4. Mail Server Setup

#### For Development (Mailpit)
Start the local mail server for development:
```bash
docker/start-mailpit.sh
```

This will start a Mailpit container that:
- Provides a local SMTP server on port 1025
- Offers a web interface at http://localhost:8025 to view sent emails
- Allows you to test email functionality without sending real emails

Visit http://localhost:8025 to view all emails sent by the application during development.

#### For Production
Configure your production mail server settings in the `.env` file. You can use any SMTP server.

**Example: Mailgun Configuration**
Add these settings to your `.env` file:
```bash
EMAIL_HOST=smtp.mailgun.org
EMAIL_PORT=587  # Using port 587 for STARTTLS
EMAIL_TLS=true  # Set to true as Mailgun requires TLS for authentication
EMAIL_USERNAME=YOUR_USERNAME
EMAIL_PASSWORD=YOUR_PASSWORD
EMAIL_FROM=YOUR_USERNAME  # Using the same email as the username
```

**Other Mail Providers**
You can use any SMTP server by updating the `EMAIL_*` variables in your `.env` file according to your provider's settings.

### 5. Install Development Tools

#### Install sqlc (Required for code generation)
```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

## Complete Setup Summary

1. **Backend server**: 
   - `cd cmd/loginv2`
   - Setup `.env` file following `.env.example`
   - Start backend server: `go run main.go`

2. **Frontend**:
   - `cd frontend`
   - Install npm if needed
   - `npm run dev`

3. **Database setup**: Follow the database setup section above

4. **Mail server setup**: 
   - For development: `docker/start-mailpit.sh` and visit localhost:8025
   - For production: Configure mail server settings in .env file

5. **Install sqlc**: `go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`

## Access Points

- **Frontend Application**: http://localhost:3000
- **Backend API**: http://localhost:4000
- **Database**: localhost:5432 (database: idm_db, user: idm)
