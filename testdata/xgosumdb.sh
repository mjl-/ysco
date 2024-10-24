#!/bin/sh
set -ex

cd /tmp
export HOME=/tmp

# Tested with v0.0.0-20241012103703-0cf896118170.
GOBIN=$PWD CGO_ENABLED=0 go install github.com/mjl-/xgosumdb@v0.0.0-20241012103703-0cf896118170

# Prime with toolchains.
./xgosumdb -initkeys 'PRIVATE+KEY+localhost+7af406a6+AR65vBDzmd0yI/rsoMwbg5sYgFWIF2Z3TgtWaGxWEu1+ localhost+7af406a6+AfWA0P/5hn0K1/QybqsBg3fD+9XzPNB/v1QG73x/K8Gi'  -loglevel debug -manualadd <<EOF
golang.org/toolchain v0.0.1-go1.23.1.linux-amd64 h1:TmiC7kE4hHuA7UwTcrWUtL/Curn//Xchpqc+HHYEv2M=
golang.org/toolchain v0.0.1-go1.23.1.linux-amd64/go.mod h1:8wlg68NqwW7eMnI1aABk/C2pDYXj8mrMY4TyRfiLeS0=
EOF

./xgosumdb -loglevel debug -manualadd <<EOF
golang.org/toolchain v0.0.1-go1.23.2.linux-amd64 h1:IDEN8pZmbj0ITWVUw1brvyauTB4Z/eKiSRvjtC5Jumw=
golang.org/toolchain v0.0.1-go1.23.2.linux-amd64/go.mod h1:8wlg68NqwW7eMnI1aABk/C2pDYXj8mrMY4TyRfiLeS0=
EOF

./xgosumdb -loglevel debug -manualadd <<EOF
golang.org/toolchain v0.0.1-go1.22.8.linux-amd64 h1:sJePZPqqnwpRH8RGjomeVBwFJW3QuQ8i85HCBzxanXE=
golang.org/toolchain v0.0.1-go1.22.8.linux-amd64/go.mod h1:8wlg68NqwW7eMnI1aABk/C2pDYXj8mrMY4TyRfiLeS0=
EOF

./xgosumdb -addr :3080 -proxy http://goproxy:2080 -loglevel debug
