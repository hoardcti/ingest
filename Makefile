# HoardCTI ingest.
#
# `make help` lists the targets. `make check` is what CI runs.

GO           ?= go
BIN          ?= bin/ingest
TEST_DB_URL  ?= postgres://hoardcti:hoardcti@localhost:5432/hoardcti_test
DEV_DB_URL   ?= postgres://hoardcti:hoardcti@localhost:5432/hoardcti
DEV_REDIS_URL?= redis://localhost:6379/0

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the ingest binary into bin/
	$(GO) build -trimpath -o $(BIN) ./cmd/ingest

.PHONY: test
test: ## Run the unit tests (database tests are skipped)
	$(GO) test ./...

.PHONY: test-db
test-db: ## Create the test database in the running Postgres container
	@docker compose exec -T postgres createdb -U hoardcti hoardcti_test 2>/dev/null \
		|| echo "hoardcti_test already exists"

.PHONY: test-integration
test-integration: test-db ## Run every test, including the ones that need Postgres
	HOARDCTI_TEST_DATABASE_URL=$(TEST_DB_URL) $(GO) test ./... -count=1

.PHONY: race
race: test-db ## Run the tests under the race detector
	HOARDCTI_TEST_DATABASE_URL=$(TEST_DB_URL) $(GO) test -race ./... -count=1

.PHONY: cover
cover: ## Run the tests and open the coverage report
	HOARDCTI_TEST_DATABASE_URL=$(TEST_DB_URL) $(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format the Go sources
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if anything is unformatted
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "unformatted files:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: tidy-check
tidy-check: ## Fail if go.mod or go.sum would change
	$(GO) mod tidy -diff

.PHONY: contract
contract: ## Validate the example envelopes against the contract
	$(GO) run ./cmd/ingest validate contract/examples/*.json

.PHONY: check
check: fmt-check vet tidy-check test ## Everything CI runs, minus the database tests

.PHONY: up
up: ## Start Postgres and Valkey
	docker compose up -d

.PHONY: metrics
metrics: ## Start Prometheus alongside the stack, scraping the ingest service
	docker compose --profile metrics up -d --build prometheus
	@echo "Prometheus: http://localhost:9090  (targets: /targets, graphs: /graph)"
	@echo "It scrapes host.docker.internal:8080, so it works against 'make serve'"
	@echo "or the containerised service. Rules: deploy/prometheus/rules.yml"

.PHONY: down
down: ## Stop the development stack, including any profiles
	docker compose --profile full --profile metrics down

.PHONY: reset
reset: ## Destroy the development stack and its data
	docker compose --profile full --profile metrics down --volumes

.PHONY: migrate
migrate: ## Apply migrations to the development database
	HOARDCTI_DATABASE_URL=$(DEV_DB_URL) $(GO) run ./cmd/ingest migrate up

.PHONY: migrate-status
migrate-status: ## Show migration status for the development database
	HOARDCTI_DATABASE_URL=$(DEV_DB_URL) $(GO) run ./cmd/ingest migrate status

.PHONY: seed
seed: ## Register the example sources and load the example envelopes
	HOARDCTI_DATABASE_URL=$(DEV_DB_URL) HOARDCTI_REDIS_URL=$(DEV_REDIS_URL) \
		HOARDCTI_AUTO_REGISTER_SOURCES=true \
		$(GO) run ./cmd/ingest load contract/examples/indicator-batch.json \
			contract/examples/cve-enrichment.json \
			contract/examples/breach-with-inline-raw.json

.PHONY: serve
serve: ## Run the ingest service against the development stack
	HOARDCTI_DATABASE_URL=$(DEV_DB_URL) HOARDCTI_REDIS_URL=$(DEV_REDIS_URL) \
		HOARDCTI_LOG_FORMAT=text HOARDCTI_LOG_LEVEL=debug \
		HOARDCTI_AUTO_REGISTER_SOURCES=true HOARDCTI_HTTP_TOKENS=dev-token \
		$(GO) run ./cmd/ingest serve

.PHONY: image
image: ## Build the container image
	docker build -t hoardcti/ingest:dev .

.PHONY: clean
clean: ## Remove build output
	rm -rf bin coverage.out
