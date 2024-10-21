SOURCES := $(shell find . -mindepth 2 -name "main.go")
DESTS := $(patsubst ./%/main.go,dist/%,$(SOURCES))
ALL := dist/main $(DESTS)

all: $(ALL)
	@echo $@: Building Targets $^

dist/main:
ifneq (,$(wildcard main.go))
	$(echo Bulding main.go)
	go build -buildvcs -o $@ main.go
endif

#dist/main:
#	@echo Building $^ into $@
#	test -f main.go && go build -buildvcs -o $@ $^

dist/%: %/main.go
	@echo $@: Building $^ to $@
	go build -buildvcs -o $@ $^

dep:
	go mod tidy

clean:
	go clean
	rm -f $(ALL)

.PHONY: clean

migration-create:
# Usage: make migration-create name="migration-name"
	goose -dir migrations/idm postgres "postgres://idm:pwd@localhost/idm_db?sslmode=disable" create $(name) sql

migration-up:
	goose -dir migrations/idm postgres "postgres://idm:pwd@localhost/idm_db?sslmode=disable" up

migration-down:
	goose -dir migrations/idm postgres "postgres://idm:pwd@localhost/idm_db?sslmode=disable" down

dump-idm:
	pg_dump --schema-only -h localhost -p 5432 -U idm -d idm_db -n public > migrations/idm_db.sql

run:
	arelo -t . -p '**/*.go' -i '**/.*' -i '**/*_test.go' -- go run .

