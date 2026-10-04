# Local Postgres 18 (Homebrew). Tests wipe their own schema in a database whose name
# contains "test", and skip without TEST_DATABASE_URL.
DATABASE_URL      ?= postgres://$(USER)@localhost/duongondro
TEST_DATABASE_URL ?= postgres://$(USER)@localhost/duongondro_test
export TEST_DATABASE_URL

.PHONY: test vet gen db-setup db-new migrate serve build release deploy vectors

test: vet             ## gofmt, vet (release and DEV), every test (DEV ones too)
	go test ./...
	go test -tags DEV ./internal/...

vet:
	gofmt -l . | (! grep .) || (echo "gofmt needed"; exit 1)
	go vet ./...
	go vet -tags DEV ./...

gen:                  ## Regenerate internal/api from api/openapi.yaml and internal/db from db/
	go generate ./internal/api/
	sqlc generate

db-setup:             ## Create and migrate the local databases
	createdb duongondro 2>/dev/null || true
	createdb duongondro_test 2>/dev/null || true
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/duongondro-api migrate

db-new:               ## New migration stamped with the current UTC second: make db-new name=add_x
	@test -n "$(name)" || (echo "usage: make db-new name=snake_case_name"; exit 1)
	goose -dir db/migrations create "$(name)" sql

migrate:
	DATABASE_URL="$(DATABASE_URL)" go run ./cmd/duongondro-api migrate

serve:                ## DEV build on 127.0.0.1:8080, with POST /api/dev/session and magic links on stderr
	DATABASE_URL="$(DATABASE_URL)" RP_ID=localhost RP_ORIGINS=http://localhost:8080 \
		go run -tags DEV ./cmd/duongondro-api serve

build:
	go build -trimpath -o bin/duongondro-api ./cmd/duongondro-api

# Regenerate testdata/vectors.json after an intentional format change.
vectors:
	go test ./internal/e2ee -update

# Release builds never come from a dirty tree (the commit the apps show must exist on
# GitHub) and never contain the DEV sign-in.
release:
	@test -z "$$(git status --porcelain)" || (echo "refusing to release from a dirty tree"; git status --short; exit 1)
	go test -count=1 -run '^TestReleaseBinaryHasNoDevSession$$' ./cmd/duongondro-api
	go build -trimpath -ldflags="-s -w" -o bin/duongondro-api ./cmd/duongondro-api
	@! grep -q -a '/api/dev/session' bin/duongondro-api || (echo "the binary contains the DEV sign-in; refusing to release it"; exit 1)
	@go version -m bin/duongondro-api | grep -q 'vcs.modified=false' || (echo "binary is not stamped as clean"; exit 1)
	@echo "built $$(git rev-parse --short HEAD)"

# Builds a release for the shared FreeBSD server and deploys it (deploy/deploy.yml);
# github.com/moroz/shared-infrastructure sets up the service, database and env there.
deploy:
	cd deploy && mise exec -- ansible-playbook deploy.yml
