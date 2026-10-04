#!/usr/bin/env -S bash -euo pipefail
# Builds rel/release.tar.gz: the server binary for GOOS/GOARCH (FreeBSD/amd64 by
# default, the shared server). Migrations are embedded in the binary. As
# CodeShare's deploy/build-release.sh.
#
# Never from a dirty tree: the commit the apps show must exist on GitHub. The
# release is the plain build, without -tags DEV; the release-binary test checks a
# plain build has no dev route, and afterwards the shipped binary itself is checked.

cd "$(dirname "$0")/.."

if [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing to release from a dirty tree" >&2
  git status --short >&2
  exit 1
fi

export GOOS="${GOOS:-freebsd}"
export GOARCH="${GOARCH:-amd64}"
export CGO_ENABLED=0

rm -rf rel
mkdir -p rel

# For the machine running this, not the target
GOOS= GOARCH= go vet ./...
GOOS= GOARCH= go test -count=1 -run '^TestReleaseBinaryHasNoDevSession$' ./cmd/duongondro-api

go build -trimpath -ldflags="-s -w" -o rel/server ./cmd/duongondro-api

if grep -q -a '/api/dev/session' rel/server; then
  echo "rel/server contains the dev sign-in route; refusing to release it" >&2
  exit 1
fi
if ! go version -m rel/server | grep -q 'vcs.modified=false'; then
  echo "rel/server is not stamped as built from a clean tree" >&2
  exit 1
fi

tar_opts="--no-xattrs"
if [[ "$(uname)" = "Darwin" ]]; then
  tar_opts="$tar_opts --no-mac-metadata"
fi
cd rel && tar czf release.tar.gz $tar_opts server
echo "built $(git rev-parse --short HEAD)"
