#!/bin/sh
set -ex

cd /tmp
export HOME=/tmp

# Tested with v0.0.0-20241012103703-0cf896118170.
GOBIN=$PWD CGO_ENABLED=0 go install github.com/mjl-/xgosumdb@v0.0.0-20241012103703-0cf896118170

# Prime with toolchains.
./xgosumdb -initkeys 'PRIVATE+KEY+localhost+7af406a6+AR65vBDzmd0yI/rsoMwbg5sYgFWIF2Z3TgtWaGxWEu1+ localhost+7af406a6+AfWA0P/5hn0K1/QybqsBg3fD+9XzPNB/v1QG73x/K8Gi'  -loglevel debug -manualadd <<EOF
golang.org/toolchain v0.0.1-go1.24.1.linux-amd64 h1:+AbJFFR/Yl0P7OUo47KYyCkJGQwVW2QsKjfJalHZRnM=
golang.org/toolchain v0.0.1-go1.24.1.linux-amd64/go.mod h1:8wlg68NqwW7eMnI1aABk/C2pDYXj8mrMY4TyRfiLeS0=
EOF

./xgosumdb -loglevel debug -manualadd <<EOF
golang.org/toolchain v0.0.1-go1.24.2.linux-amd64 h1:R9IIB2RUnzzL1V20iFM8ThvETQpC28HLmNVkchhyjb0=
golang.org/toolchain v0.0.1-go1.24.2.linux-amd64/go.mod h1:8wlg68NqwW7eMnI1aABk/C2pDYXj8mrMY4TyRfiLeS0=
EOF

./xgosumdb -loglevel debug -manualadd <<EOF
golang.org/toolchain v0.0.1-go1.23.8.linux-amd64 h1:ovFsku0P6JkZA6FHZbrbBo/vcMKU+1e70vO1vZtexxI=
golang.org/toolchain v0.0.1-go1.23.8.linux-amd64/go.mod h1:8wlg68NqwW7eMnI1aABk/C2pDYXj8mrMY4TyRfiLeS0=
EOF

./xgosumdb -addr :3080 -proxy http://goproxy:2080 -loglevel debug
