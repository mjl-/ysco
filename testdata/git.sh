#!/bin/sh
set -ex

# We are started with /testdata and /testdata/git.
# We work from /tmp.

export HOME=/tmp

# We clone, modify and commit the ysco repo below, for updated module path
# (git.local instead of the github url), so the goproxy fetches from the
# webserver in this container (started below).
git config --global user.email "git@localhost"
git config --global user.name "git"

# Basic static file webserver.
mkdir -p /tmp/web/webserver
cd /tmp/web/webserver
cat >main.go <<EOF
package main

import (
	"flag"
	"log"
	"net/http"
	"runtime/debug"
)

var listen string
var certfile string
var keyfile string

func main() {
	log.SetFlags(0)
	flag.StringVar(&listen, "listen", "localhost:8080", "address to listen on")
	flag.StringVar(&certfile, "cert", "", "cert pem file for tls")
	flag.StringVar(&keyfile, "key", "", "key pem file for tls")
	flag.Parse()

	handler := http.FileServer(http.Dir("."))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s", r.URL)
		w.Header().Set("Cache-Control", "max-age=0")
		handler.ServeHTTP(w, r)
	})
	info, _ := debug.ReadBuildInfo()
	log.Println("starting webserver on", listen, "version", info.Main.Version, "goversion", info.GoVersion)
	if certfile != "" || keyfile != "" {
		log.Fatal(http.ListenAndServeTLS(listen, certfile, keyfile, nil))
	} else {
		log.Fatal(http.ListenAndServe(listen, nil))
	}
}
EOF
cat >go.mod <<EOF
module git.local/webserver

go 1.22
EOF
git init
git add main.go go.mod
git commit -m 'webserver'
git tag -a v0.0.4 -m v0.0.4
git tag -a v0.0.5 -m v0.0.5
git update-server-info
cat >index.html<<EOF
<html><head>
<meta name="go-import" content="git.local/webserver git https://git.local/webserver/.git" />
</head><body>index for webserver, for go-import meta</body></html>
EOF


# Clone ysco git repo, modify the module path from github to git.local/ysco,
# add tags for use in tests.
git clone /testdata/ysco.git /tmp/web/ysco
cd /tmp/web/ysco
sed -i s,github.com/mjl-/ysco,git.local/ysco,g go.mod *.go
git diff
git commit --amend -m test go.mod *.go
git tag -a v0.9.8 -m v0.9.8
git tag -a v0.9.9 -m v0.9.9
git update-server-info # Make plain http git clone work.
# Add html file so goproxy's go module fetch finds where to clone from.
cat >index.html<<EOF
<html><head>
<meta name="go-import" content="git.local/ysco git https://git.local/ysco/.git" />
</head><body>index for ysco, for go-import meta</body></html>
EOF

# Start https server with self-signed cert.
cd /tmp/web
# go run /tmp/webserver.go -listen :80 & # For debugging.
go run /tmp/web/webserver/main.go -key /testdata/key.pem -cert /testdata/cert.pem -listen :443
