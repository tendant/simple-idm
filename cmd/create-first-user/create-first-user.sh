#!/bin/bash

# create-first-user.sh
# Script to create the first admin user for a new simple-idm system
# 
# Usage: ./create-first-user.sh [username] [email]
#   username: Login username (default: 'super')
#   email: User email address (default: '{username}@example.com')
#
# Environment Variables:
#   DATABASE_URL: PostgreSQL connection string
#   OR individual variables:
#   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

set -euo pipefail

# Script configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADMIN_ROLE_NAME="admin"
PASSWORD_VERSION=2  # Current password version used by simple-idm

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Usage function
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [username] [email]

Creates the first admin user for a new simple-idm system.

Arguments:
  username    Login username (optional, default from .env or 'super')
  email       User email address (optional, default from .env or '{username}@example.com')

Configuration:
  The script loads configuration from .env file if present, then from environment variables.
  Copy .env.example to .env and customize for your environment.

Environment Variables:
  DATABASE_URL        PostgreSQL connection string (preferred)
  OR individual variables:
  DB_HOST             Database host (default: localhost)
  DB_PORT             Database port (default: 5432)
  DB_NAME             Database name (required)
  DB_USER             Database user (required)
  DB_PASSWORD         Database password (required)
  
  Optional configuration:
  DEFAULT_USERNAME    Default username when none provided (default: 'super')
  DEFAULT_EMAIL_DOMAIN Default email domain (default: 'example.com')

Examples:
  $SCRIPT_NAME                              # Uses defaults from .env or 'super'
  $SCRIPT_NAME admin                        # Uses 'admin' with default email domain
  $SCRIPT_NAME admin admin@company.com      # Uses specified username and email

Configuration Priority (highest to lowest):
  1. Command line arguments
  2. Environment variables
  3. .env file values
  4. Built-in defaults

The script will:
1. Load configuration from .env file (if present)
2. Create 'admin' role if it doesn't exist
3. Create login with specified username
4. Generate a secure random password and log it to console
5. Create user record with specified email
6. Associate user with admin role

EOF
}

# Load .env file if it exists
load_env_file() {
    local env_file="$SCRIPT_DIR/.env"
    
    if [[ -f "$env_file" ]]; then
        log_info "Loading configuration from .env file"
        
        # Read .env file line by line
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip empty lines and comments
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            
            # Skip lines that don't contain =
            [[ "$line" != *"="* ]] && continue
            
            # Extract key and value
            key="${line%%=*}"
            value="${line#*=}"
            
            # Remove leading/trailing whitespace from key
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"
            
            # Remove quotes from value if present
            value="${value#\"}"
            value="${value%\"}"
            value="${value#\'}"
            value="${value%\'}"
            
            # Only set if not already set in environment
            if [[ -z "${!key:-}" ]]; then
                export "$key"="$value"
            fi
        done < "$env_file"
        
        log_info "Configuration loaded from .env file"
    else
        log_info "No .env file found, using environment variables and defaults"
    fi
}

# Global flags
DEBUG_MODE=false
DRY_RUN_MODE=false

# Parse flags
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --dry-run)
            DRY_RUN_MODE=true
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# Load .env file early
load_env_file

# Parse arguments with support for .env defaults
USERNAME="${1:-${DEFAULT_USERNAME:-super}}"
if [[ -n "${2:-}" ]]; then
    EMAIL="$2"
elif [[ -n "${DEFAULT_EMAIL_DOMAIN:-}" ]]; then
    EMAIL="${USERNAME}@${DEFAULT_EMAIL_DOMAIN}"
else
    EMAIL="${USERNAME}@example.com"
fi

# Validate username
if [[ ! "$USERNAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    log_error "Invalid username. Only alphanumeric characters, underscores, and hyphens are allowed."
    exit 1
fi

# Validate email format
if [[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    log_error "Invalid email format: $EMAIL"
    exit 1
fi

# Database connection setup
setup_database_connection() {
    if [[ -n "${DATABASE_URL:-}" ]]; then
        # Use DATABASE_URL if provided
        DB_CONNECTION_STRING="$DATABASE_URL"
        log_info "Using DATABASE_URL for connection"
    else
        # Build connection string from individual variables
        DB_HOST="${DB_HOST:-localhost}"
        DB_PORT="${DB_PORT:-5432}"
        
        if [[ -z "${DB_NAME:-}" ]]; then
            log_error "DB_NAME environment variable is required"
            exit 1
        fi
        
        if [[ -z "${DB_USER:-}" ]]; then
            log_error "DB_USER environment variable is required"
            exit 1
        fi
        
        if [[ -z "${DB_PASSWORD:-}" ]]; then
            log_error "DB_PASSWORD environment variable is required"
            exit 1
        fi
        
        DB_CONNECTION_STRING="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
        log_info "Using individual DB variables for connection"
    fi
}

# Test database connection
test_database_connection() {
    log_info "Testing database connection..."
    if ! psql "$DB_CONNECTION_STRING" -c "SELECT 1;" > /dev/null 2>&1; then
        log_error "Failed to connect to database. Please check your connection settings."
        exit 1
    fi
    log_success "Database connection successful"
}

# Check if required tools are available
check_dependencies() {
    local missing_tools=()
    
    if ! command -v psql &> /dev/null; then
        missing_tools+=("psql")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install PostgreSQL client and Python 3"
        exit 1
    fi
}

# Generate secure random password
generate_password() {
    # Generate a 16-character password with mixed case, numbers, and special characters
    python3 -c "
import secrets
import string

# Define character sets
uppercase = string.ascii_uppercase
lowercase = string.ascii_lowercase
digits = string.digits
special = '!@#$%^&*()-_=+[]{}|;:,.<>?'

# Ensure at least one character from each set
password = [
    secrets.choice(uppercase),
    secrets.choice(lowercase),
    secrets.choice(digits),
    secrets.choice(special)
]

# Fill the rest with random characters from all sets
all_chars = uppercase + lowercase + digits + special
for _ in range(12):  # 16 total - 4 already added
    password.append(secrets.choice(all_chars))

# Shuffle the password
secrets.SystemRandom().shuffle(password)
print(''.join(password))
"
}

# Hash password using bcrypt (compatible with Go's bcrypt)
hash_password() {
    local password="$1"
    python3 -c "
import bcrypt
import sys

password = sys.argv[1].encode('utf-8')
# Use cost 12 (same as Go's default bcrypt cost)
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
print(hashed.decode('utf-8'))
" "$password"
}

# Execute SQL with error handling
execute_sql() {
    local sql="$1"
    local description="$2"
    
    log_info "$description"
    if [[ "$DEBUG_MODE" == "true" ]]; then
        log_info "Executing SQL: $sql"
        if ! psql "$DB_CONNECTION_STRING" -c "$sql"; then
            log_error "Failed to execute: $description"
            return 1
        fi
    else
        if ! psql "$DB_CONNECTION_STRING" -c "$sql" > /dev/null 2>&1; then
            log_error "Failed to execute: $description"
            log_error "Run with --debug flag to see detailed error messages"
            return 1
        fi
    fi
    return 0
}

# Execute SQL with detailed error reporting
execute_sql_with_debug() {
    local sql="$1"
    local description="$2"
    
    log_info "$description"
    if [[ "$DEBUG_MODE" == "true" ]]; then
        log_info "Executing SQL: $sql"
    fi
    
    local result
    local exit_code
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        result=$(psql "$DB_CONNECTION_STRING" -c "$sql" 2>&1)
        exit_code=$?
    else
        result=$(psql "$DB_CONNECTION_STRING" -c "$sql" 2>&1)
        exit_code=$?
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log_error "Failed to execute: $description"
        if [[ "$DEBUG_MODE" == "true" ]]; then
            log_error "SQL Error: $result"
        else
            log_error "Run with --debug flag to see detailed error messages"
        fi
        return 1
    fi
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        log_info "SQL executed successfully"
    fi
    return 0
}

# Execute SQL and return result
execute_sql_with_result() {
    local sql="$1"
    psql "$DB_CONNECTION_STRING" -t -c "$sql" 2>/dev/null | xargs
}

# Check if admin role exists
check_admin_role_exists() {
    local count
    count=$(execute_sql_with_result "SELECT COUNT(*) FROM roles WHERE name = '$ADMIN_ROLE_NAME';")
    [[ "$count" -gt 0 ]]
}

# Create admin role
create_admin_role() {
    if check_admin_role_exists; then
        log_info "Admin role '$ADMIN_ROLE_NAME' already exists"
        return 0
    fi
    
    local sql="INSERT INTO roles (name, description) VALUES ('$ADMIN_ROLE_NAME', 'System Administrator');"
    execute_sql "$sql" "Creating admin role '$ADMIN_ROLE_NAME'"
    log_success "Admin role '$ADMIN_ROLE_NAME' created"
}

# Check if username exists
check_username_exists() {
    local username="$1"
    local count
    count=$(execute_sql_with_result "SELECT COUNT(*) FROM login WHERE username = '$username';")
    [[ "$count" -gt 0 ]]
}

# Check if email exists
check_email_exists() {
    local email="$1"
    local count
    count=$(execute_sql_with_result "SELECT COUNT(*) FROM users WHERE email = '$email';")
    [[ "$count" -gt 0 ]]
}

# Create login entry
create_login() {
    local username="$1"
    local password="$2"
    local hashed_password="$3"
    
    if check_username_exists "$username"; then
        log_error "Username '$username' already exists"
        exit 1
    fi
    
    local now=$(date -u +"%Y-%m-%d %H:%M:%S")
    local sql="
    INSERT INTO login (
        username, 
        password, 
        password_version,
        created_at,
        updated_at,
        two_factor_enabled,
        password_updated_at,
        password_expires_at
    ) VALUES (
        '$username', 
        decode('$(echo -n "$hashed_password" | base64)', 'base64'),
        $PASSWORD_VERSION,
        '$now',
        '$now',
        false,
        '$now',
        '$now'::timestamp + interval '90 days'
    );"
    
    execute_sql "$sql" "Creating login for username '$username'"
    log_success "Login created for username '$username'"
    
    # Return the login UUID
    execute_sql_with_result "SELECT uuid FROM login WHERE username = '$username';"
}

# Create user entry
create_user() {
    local email="$1"
    local login_id="$2"
    
    if check_email_exists "$email"; then
        log_error "Email '$email' already exists"
        exit 1
    fi
    
    local now=$(date -u +"%Y-%m-%d %H:%M:%S")
    local sql="
    INSERT INTO users (
        email,
        login_id,
        created_at,
        last_modified_at
    ) VALUES (
        '$email',
        '$login_id',
        '$now',
        '$now'
    );"
    
    execute_sql "$sql" "Creating user with email '$email'"
    log_success "User created with email '$email'"
    
    # Return the user UUID
    execute_sql_with_result "SELECT uuid FROM users WHERE email = '$email';"
}

# Create user-role association
create_user_role() {
    local user_id="$1"
    local role_id
    
    # Get admin role UUID
    role_id=$(execute_sql_with_result "SELECT uuid FROM roles WHERE name = '$ADMIN_ROLE_NAME';")
    
    if [[ -z "$role_id" ]]; then
        log_error "Admin role not found"
        exit 1
    fi
    log_info "Admin role found"
    local sql="INSERT INTO user_roles (user_uuid, role_uuid) VALUES ('$user_id', '$role_id');"
    execute_sql "$sql" "Associating user with admin role"
    log_success "User associated with admin role"
}

# Main execution function
main() {
    log_info "Starting admin user creation process..."
    log_info "Username: $USERNAME"
    log_info "Email: $EMAIL"
    
    # Setup and validate environment
    check_dependencies
    setup_database_connection
    test_database_connection
    
    # Generate password
    log_info "Generating secure password..."
    local password
    password=$(generate_password)
    
    if [[ -z "$password" ]]; then
        log_error "Failed to generate password"
        exit 1
    fi
    
    # Hash password
    log_info "Hashing password..."
    local hashed_password
    hashed_password=$(hash_password "$password")
    
    if [[ -z "$hashed_password" ]]; then
        log_error "Failed to hash password"
        exit 1
    fi
    
    # Execute database operations in a transaction
    log_info "Executing database operations..."
    
    local transaction_sql="
    BEGIN;
    
    -- Create admin role if not exists
    INSERT INTO roles (name, description) 
    SELECT '$ADMIN_ROLE_NAME', 'System Administrator'
    WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = '$ADMIN_ROLE_NAME');
    
    -- Create login
    INSERT INTO login (
        username, 
        password
    ) VALUES (
        '$USERNAME', 
        decode('$(echo -n "$hashed_password" | base64)', 'base64')
    );
    
    -- Create user
    INSERT INTO users (
        email,
        login_id,
        created_at,
        last_modified_at
    ) VALUES (
        '$EMAIL',
        (SELECT id FROM login WHERE username = '$USERNAME'),
        NOW(),
        NOW()
    );
    
    -- Create user-role association
    INSERT INTO user_roles (user_id, role_id) 
    VALUES (
        (SELECT id FROM users WHERE email = '$EMAIL'),
        (SELECT id FROM roles WHERE name = '$ADMIN_ROLE_NAME')
    );
    
    COMMIT;
    "
    
    if ! execute_sql_with_debug "$transaction_sql" "Executing transaction to create admin user"; then
        log_error "Failed to create admin user. Transaction rolled back."
        exit 1
    fi
    
    # Get created IDs for confirmation
    local login_id user_id
    login_id=$(execute_sql_with_result "SELECT id FROM login WHERE username = '$USERNAME';")
    user_id=$(execute_sql_with_result "SELECT id FROM users WHERE email = '$EMAIL';")

    # Display results
    echo
    log_success "Admin user created successfully!"
    echo
    echo "=================================="
    echo "ADMIN USER DETAILS"
    echo "=================================="
    echo "Username: $USERNAME"
    echo "Email: $EMAIL"
    echo "Password: $password"
    echo "Login ID: $login_id"
    echo "User ID: $user_id"
    echo "Role: $ADMIN_ROLE_NAME"
    echo "=================================="
    echo
    log_warning "IMPORTANT: Save the password above securely!"
    log_warning "This password will not be displayed again."
    echo
    log_info "You can now log in to the simple-idm system with these credentials."
    log_info "It is recommended to change the password after first login."
}

# Check if bcrypt is available in Python
check_bcrypt() {
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        log_error "Python bcrypt library is not installed."
        log_error "Please install it with: pip3 install bcrypt"
        exit 1
    fi
}

# Add bcrypt check to dependencies
check_dependencies() {
    local missing_tools=()
    
    if ! command -v psql &> /dev/null; then
        missing_tools+=("psql")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install PostgreSQL client and Python 3"
        exit 1
    fi
    
    # Check bcrypt availability
    check_bcrypt
}

# Run main function
main "$@"
