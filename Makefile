# Database configuration defaults (can be overridden by .env or environment variables)
IDM_PG_HOST ?= localhost
IDM_PG_PORT ?= 5432
IDM_PG_DATABASE ?= idm_db
IDM_PG_USER ?= idm
IDM_PG_PASSWORD ?= pwd
IDM_PG_SCHEMA ?= public

# Load .env file if it exists (search in common locations)
# Note: Environment variables take precedence over .env file values
-include .env

SOURCES := $(shell find . -mindepth 2 -name "main.go")
DESTS := $(patsubst ./%/main.go,dist/%,$(SOURCES))
ALL := $(DESTS)

GOARCH ?= amd64
GOOS ?= linux

# Construct PostgreSQL connection string with schema in search_path
# Note: The search_path parameter determines which schema migrations will target.
# Tables created without explicit schema qualification will be created in the first schema
# in the search_path (IDM_PG_SCHEMA). This allows users to control the target schema
# via the IDM_PG_SCHEMA environment variable.
#
# We use ONLY the target schema (not public) to ensure goose creates its tracking table
# in the correct schema. This prevents conflicts with other applications' goose tables.
# UUID generation uses gen_random_uuid() which doesn't require public schema access.
PG_CONN_STRING := postgres://$(IDM_PG_USER):$(IDM_PG_PASSWORD)@$(IDM_PG_HOST):$(IDM_PG_PORT)/$(IDM_PG_DATABASE)?sslmode=disable&search_path=$(IDM_PG_SCHEMA)

all: $(ALL)
	@echo $@: Building Targets $^

dist/%: %/main.go
	@echo $@: Building $^ to $@
	GOARCH=$(GOARCH) GOOS=$(GOOS) go build -buildvcs -o $@ $^

deps:
	go mod tidy

clean:
	go clean
	rm -f $(ALL)

.PHONY: all deps clean run schema-create schema-load seed \
        migrate-validate migrate-verify migrate-create \
        migrate-up migrate-down migrate-status dump-idm dump-db

# ==============================================================================
# Database Schema Management
# ==============================================================================
# These targets manage database schemas and migrations. The target schema is
# controlled by the IDM_PG_SCHEMA environment variable (default: public).
#
# Examples:
#   make migrate-up                          # Use default schema (public)
#   IDM_PG_SCHEMA=idm make migrate-up        # Use custom schema (idm)
#   make migrate-status                      # Check migration status
# ==============================================================================

schema-create:
	@echo "📋 Creating schema '$(IDM_PG_SCHEMA)' if it doesn't exist..."
	@PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) -c "CREATE SCHEMA IF NOT EXISTS $(IDM_PG_SCHEMA);" > /dev/null
	@echo "✓ Schema '$(IDM_PG_SCHEMA)' is ready"

migrate-validate:
	@echo "🔍 Validating migration configuration..."
	@echo "  Database: $(IDM_PG_DATABASE)"
	@echo "  Target Schema: $(IDM_PG_SCHEMA)"
	@echo "  Host: $(IDM_PG_HOST):$(IDM_PG_PORT)"
	@if [ "$(IDM_PG_SCHEMA)" = "" ]; then \
		echo "❌ ERROR: IDM_PG_SCHEMA is not set"; \
		exit 1; \
	fi
	@if [ "$(IDM_PG_SCHEMA)" != "public" ]; then \
		echo "⚠️  WARNING: Using non-default schema '$(IDM_PG_SCHEMA)'"; \
	fi
	@echo "  Checking database connection..."
	@PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) -c "SELECT 1;" > /dev/null 2>&1 || \
		(echo "❌ ERROR: Cannot connect to database"; exit 1)
	@echo "✓ Validation passed"

migrate-verify:
	@echo "🔍 Verifying migrations were applied to schema '$(IDM_PG_SCHEMA)'..."
	@PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) \
		-c "SELECT schemaname FROM pg_tables WHERE tablename = 'goose_db_version';" -t | grep -q "$(IDM_PG_SCHEMA)" && \
		echo "✓ Migration tracking table found in schema '$(IDM_PG_SCHEMA)'" || \
		(echo "⚠️  WARNING: Migration tracking table not found in schema '$(IDM_PG_SCHEMA)'"; exit 0)

migrate-create:
	@echo "📝 Creating new migration file..."
# Usage: make migrate-create name="migration-name"
	@if [ "$(name)" = "" ]; then \
		echo "❌ ERROR: Please provide a migration name: make migrate-create name=\"your-migration-name\""; \
		exit 1; \
	fi
	goose -dir migrations/idm postgres "$(PG_CONN_STRING)" create $(name) sql
	@echo "✓ Migration file created"

migrate-up: migrate-validate schema-create
	@echo "🚀 Running migrations on schema '$(IDM_PG_SCHEMA)'..."
	@goose -dir migrations/idm postgres "$(PG_CONN_STRING)" up
	@$(MAKE) migrate-verify
	@echo "✓ Migrations completed successfully"

migrate-down:
	@echo "⏪ Rolling back last migration on schema '$(IDM_PG_SCHEMA)'..."
	@echo "⚠️  WARNING: This will revert the last migration!"
	@goose -dir migrations/idm postgres "$(PG_CONN_STRING)" down
	@echo "✓ Migration rolled back"

dump-idm:
	PGPASSWORD=$(IDM_PG_PASSWORD) pg_dump --schema-only -n $(IDM_PG_SCHEMA) -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) > migrations/idm_db.sql

dump-db:
	PGPASSWORD=$(IDM_PG_PASSWORD) pg_dump -n $(IDM_PG_SCHEMA) -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) > idm_db_all.sql

run:
	arelo -t . -p '**/*.go' -i '**/.*' -i '**/*_test.go' -- go run .

schema-load: schema-create
	PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) -c "SET search_path TO $(IDM_PG_SCHEMA),public" -f migrations/idm_db.sql

seed:
	PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) -c "SET search_path TO $(IDM_PG_SCHEMA),public" -f migrations/seed.sql

migrate-status:
	@echo "📊 Migration status for schema '$(IDM_PG_SCHEMA)':"
	@goose -dir migrations/idm postgres "$(PG_CONN_STRING)" status
