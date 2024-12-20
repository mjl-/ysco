#!/bin/sh
set -x
# Remove stale versions of git.local and localhost from previous test runs.
rm -r /go/pkg/mod/git.local /go/pkg/mod/cache/download/git.local /go/pkg/mod/cache/vcs /go/pkg/sumdb/localhost /go/pkg/mod/cache/download/sumdb/localhost
set -e

# We need the integration_test.go, and we want to work in an isolated directory
# so previous binaries aren't in the way (could cause trouble with
# old-binaries-cleanup code).
git clone /testdata/git /tmp/ysco

cd /tmp/ysco
export HOME=$PWD

# It would be nice to build ysco with -cover, for integration-level test
# coverage. However, ysco execs itself as part of the tests, with new binaries
# fetched through gobuild (which doesn't build with -cover), so too hard for
# now. https://go.dev/blog/integration-test-coverage

CGO_ENABLED=0 GOBIN=$PWD GOSUMDB='localhost+7af406a6+AfWA0P/5hn0K1/QybqsBg3fD+9XzPNB/v1QG73x/K8Gi http://xgosumdb:3080' GOPROXY=http://goproxy:2080 go install git.local/ysco@v0.9.9
mv ysco ysco-v0.9.9
# go version -m ysco

CGO_ENABLED=0 GOBIN=$PWD GOSUMDB='localhost+7af406a6+AfWA0P/5hn0K1/QybqsBg3fD+9XzPNB/v1QG73x/K8Gi http://xgosumdb:3080' GOPROXY=http://goproxy:2080 go install git.local/webserver@v0.0.5
mv webserver webserver-v0.0.5
ln -s webserver-v0.0.5 webserver

CGO_ENABLED=0 go test -v -tags integration
