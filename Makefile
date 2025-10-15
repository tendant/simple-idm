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
-include cmd/loginv2/.env

SOURCES := $(shell find . -mindepth 2 -name "main.go")
DESTS := $(patsubst ./%/main.go,dist/%,$(SOURCES))
ALL := dist/main $(DESTS)

GOARCH ?= amd64
GOOS ?= linux

# Construct PostgreSQL connection string with schema in search_path
PG_CONN_STRING := postgres://$(IDM_PG_USER):$(IDM_PG_PASSWORD)@$(IDM_PG_HOST):$(IDM_PG_PORT)/$(IDM_PG_DATABASE)?sslmode=disable&search_path=$(IDM_PG_SCHEMA)

all: $(ALL)
	@echo $@: Building Targets $^

dist/main:
ifneq (,$(wildcard main.go))
	$(echo Bulding main.go)
	GOARCH=$(GOARCH) GOOS=$(GOOS) go build -buildvcs -o $@ main.go
endif

#dist/main:
#	@echo Building $^ into $@
#	test -f main.go && go build -buildvcs -o $@ $^

dist/%: %/main.go
	@echo $@: Building $^ to $@
	GOARCH=$(GOARCH) GOOS=$(GOOS) go build -buildvcs -o $@ $^

dep:
	go mod tidy

clean:
	go clean
	rm -f $(ALL)

.PHONY: clean

schema-create:
	PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) -c "CREATE SCHEMA IF NOT EXISTS $(IDM_PG_SCHEMA);"

migration-create:
# Usage: make migration-create name="migration-name"
	goose -dir migrations/idm postgres "$(PG_CONN_STRING)" create $(name) sql

migration-up: schema-create
	goose -dir migrations/idm postgres "$(PG_CONN_STRING)" up

migration-down:
	goose -dir migrations/idm postgres "$(PG_CONN_STRING)" down

dump-idm:
	PGPASSWORD=$(IDM_PG_PASSWORD) pg_dump --schema-only -n $(IDM_PG_SCHEMA) -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) > migrations/idm_db.sql

dump-db:
	PGPASSWORD=$(IDM_PG_PASSWORD) pg_dump -n $(IDM_PG_SCHEMA) -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) > idm_db_all.sql

run:
	arelo -t . -p '**/*.go' -i '**/.*' -i '**/*_test.go' -- go run .

schema-load: schema-create
	PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) -c "SET search_path TO $(IDM_PG_SCHEMA)" -f migrations/idm_db.sql

seed:
	PGPASSWORD=$(IDM_PG_PASSWORD) psql -h $(IDM_PG_HOST) -p $(IDM_PG_PORT) -U $(IDM_PG_USER) -d $(IDM_PG_DATABASE) -c "SET search_path TO $(IDM_PG_SCHEMA)" -f migrations/seed.sql

migration-status:
	goose -dir migrations/idm postgres "$(PG_CONN_STRING)" status

