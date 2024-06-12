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

migration-create-idm:
# Usaged: make migration-create-idm name="demo"
	migrate create -dir "migrations/idm" -format "20060102150405" -ext sql $(name)

migrate-up-idm:
	migrate -source file://migrations/idm -database postgres://idm_db:pwd@localhost:5432/idm_db?sslmode=disable up

migrate-down-idm:
	migrate -source file://migrations/idm -database postgres://idm_db:pwd@localhost:5432/idm_db?sslmode=disable down

run:
	arelo -t . -p '**/*.go' -i '**/.*' -i '**/*_test.go' -- go run .

