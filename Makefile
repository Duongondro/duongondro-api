.PHONY: test test-db build release vectors run

test:
	gofmt -l . | (! grep .) || (echo "gofmt needed"; exit 1)
	go vet ./...
	go test ./...

# Integration tests against the local PostgreSQL; each test gets its own
# schema, so packages run in parallel.
TEST_DATABASE_URL ?= postgres://postgres@127.0.0.1:54329/duongondro_test?sslmode=disable
test-db:
	TEST_DATABASE_URL='$(TEST_DATABASE_URL)' go test -count=1 ./...

build:
	go build -trimpath -o bin/duongondro-api ./cmd/duongondro-api

run:
	go run ./cmd/duongondro-api

# Regenerate testdata/vectors.json after an intentional format change.
vectors:
	go test ./internal/e2ee -update

# Release builds never come from a dirty tree: the commit shown in the apps'
# Settings must exist on GitHub.
release:
	@test -z "$$(git status --porcelain)" || (echo "refusing to release from a dirty tree"; git status --short; exit 1)
	go build -trimpath -o bin/duongondro-api ./cmd/duongondro-api
	@go version -m bin/duongondro-api | grep -q 'vcs.modified=false' || (echo "binary is not stamped as clean"; exit 1)
	@echo "built $$(git rev-parse --short HEAD)"
