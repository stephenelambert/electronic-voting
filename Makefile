POSTGRES_VERSION = 17
GOLANGCI_LINT_VERSION = v2.15.0-alpine

launch-db:
	docker run -d --name electronic-voting-postgres -p 127.0.0.1:5432:5432 \
	 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=password \
	 postgres:$(POSTGRES_VERSION)

stop-db:
	docker container stop electronic-voting-postgres

remove-db:
	docker container rm -f electronic-voting-postgres

lint-api:
	docker run -t --rm -v $(PWD)/backend:/app -w /app golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) golangci-lint run ./...