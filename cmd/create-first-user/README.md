# Create First User Script

This script creates the first admin user for a new simple-idm system. It automates the process of setting up an initial administrator account with proper role assignments.

## Features

- Creates 'admin' role if it doesn't exist
- Creates login with specified username (default: 'super')
- Generates a secure random password and displays it in the console
- Creates user record with specified email (default: '{username}@example.com')
- Associates user with admin role
- Uses proper bcrypt password hashing compatible with simple-idm
- Executes all operations in a database transaction for atomicity
- Comprehensive error handling and validation

## Prerequisites

### Required Tools
- `psql` (PostgreSQL client)
- `python3` with `bcrypt` library

### Install Python bcrypt
```bash
pip3 install bcrypt
```

### Database Setup
The script requires a PostgreSQL database with the simple-idm schema already migrated. Make sure you have run all database migrations before using this script.

## Usage

```bash
./create-first-user.sh [username] [email]
```

### Arguments
- `username` (optional): Login username (default: 'super')
- `email` (optional): User email address (default: '{username}@example.com')

### Examples

```bash
# Create user 'super' with email 'super@example.com'
./create-first-user.sh

# Create user 'admin' with email 'admin@example.com'
./create-first-user.sh admin

# Create user 'admin' with custom email
./create-first-user.sh admin admin@company.com

# Show help
./create-first-user.sh --help
```

## Configuration

### Option 1: .env File (Recommended)
Copy the example configuration file and customize it:

```bash
cp .env.example .env
# Edit .env with your database settings
./create-first-user.sh
```

Example `.env` file:
```bash
# Database Configuration (Option 1: Use DATABASE_URL)
DATABASE_URL=postgresql://username:password@localhost:5432/simple_idm

# Database Configuration (Option 2: Individual variables)
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=simple_idm
# DB_USER=postgres
# DB_PASSWORD=your_password_here

# Script Configuration (Optional)
DEFAULT_USERNAME=admin
DEFAULT_EMAIL_DOMAIN=company.com
```

### Option 2: Environment Variables
```bash
export DATABASE_URL="postgresql://username:password@host:port/database"
./create-first-user.sh
```

Or using individual variables:
```bash
export DB_HOST="localhost"        # default: localhost
export DB_PORT="5432"            # default: 5432
export DB_NAME="simple_idm"      # required
export DB_USER="postgres"        # required
export DB_PASSWORD="password"    # required
./create-first-user.sh
```

### Configuration Priority
The script loads configuration in this order (highest to lowest priority):
1. **Command line arguments** - Override everything
2. **Environment variables** - Override .env file values
3. **.env file values** - Override built-in defaults
4. **Built-in defaults** - Fallback values

### Additional Configuration Options
- `DEFAULT_USERNAME`: Default username when none provided (default: 'super')
- `DEFAULT_EMAIL_DOMAIN`: Default email domain (default: 'example.com')

## Output

Upon successful execution, the script will display:

```
==================================
ADMIN USER DETAILS
==================================
Username: super
Email: super@example.com
Password: Xy9#mK2$pL8@nQ4!
Login ID: 123e4567-e89b-12d3-a456-426614174000
User ID: 987fcdeb-51a2-43d1-9f12-123456789abc
Role: admin
==================================

IMPORTANT: Save the password above securely!
This password will not be displayed again.

You can now log in to the simple-idm system with these credentials.
It is recommended to change the password after first login.
```

## Security Notes

1. **Password Security**: The script generates a 16-character password with:
   - Uppercase letters
   - Lowercase letters
   - Numbers
   - Special characters

2. **Password Hashing**: Uses bcrypt with cost 12 (same as Go's default)

3. **Password Storage**: The generated password is only displayed once in the console. Make sure to save it securely.

4. **Database Security**: All operations are executed in a transaction to ensure data consistency.

## Error Handling

The script includes comprehensive error handling for:

- Missing dependencies (psql, python3, bcrypt)
- Database connection failures
- Duplicate usernames or emails
- Invalid input validation
- Transaction failures with automatic rollback

## Validation

The script validates:

- Username format (alphanumeric, underscores, hyphens only)
- Email format (basic RFC-compliant validation)
- Database connectivity
- Required environment variables

## Troubleshooting

### Common Issues

1. **"psql: command not found"**
   ```bash
   # macOS
   brew install postgresql
   
   # Ubuntu/Debian
   sudo apt-get install postgresql-client
   
   # CentOS/RHEL
   sudo yum install postgresql
   ```

2. **"Python bcrypt library is not installed"**
   ```bash
   pip3 install bcrypt
   ```

3. **"Failed to connect to database"**
   - Check your database connection parameters
   - Ensure the database server is running
   - Verify network connectivity
   - Check firewall settings

4. **"Username 'admin' already exists"**
   - The username is already taken
   - Choose a different username
   - Or check if you need to use the existing account

5. **"Email 'admin@example.com' already exists"**
   - The email is already in use
   - Choose a different email address

### Debug Mode

For debugging, you can run individual SQL commands manually:

```bash
# Test database connection
psql "$DATABASE_URL" -c "SELECT 1;"

# Check existing roles
psql "$DATABASE_URL" -c "SELECT * FROM roles;"

# Check existing users
psql "$DATABASE_URL" -c "SELECT username FROM login;"
```

## Integration

This script is designed to be used during the initial setup of a simple-idm system. It should be run:

1. After database migrations are complete
2. Before starting the simple-idm application
3. As part of deployment automation scripts

## License

This script is part of the simple-idm project and follows the same license terms.
