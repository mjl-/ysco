#!/bin/sh
set -ex

# We are started with /testdata. And with /testdata/sdk to reuse SDKs over restarts.

cd /tmp
export HOME=/tmp
GOBIN=$PWD CGO_ENABLED=0 go install github.com/mjl-/gobuild@v0.0.27

./gobuild serve -listen-http :4080 -listen-admin :4081 /testdata/gobuild.conf
