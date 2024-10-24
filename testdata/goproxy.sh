#!/bin/sh
set -ex

cd /tmp
export HOME=/tmp

GOBIN=$PWD CGO_ENABLED=0 go install github.com/goproxy/goproxy/cmd/goproxy@v0.17.2

GOSUMDB=off \
	GOPROXY=direct \
	GIT_SSL_NO_VERIFY=true \
	GOINSECURE=git.local/* \
	SSL_CERT_FILE=/testdata/cert.pem \
	./goproxy server --address :2080

# GOMODCACHE=$PWD/goproxy-gomodcache
