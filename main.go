package main

/*
- todo: replace beta.gobuilds.org verifierkey once gobuilds.org is out of beta.
- todo: add ctl unix domain socket and subcommands to influence behaviour. so web interface isn't needed.
- todo: do something for updating to prerelease versions, go proxy and gopherwatch don't list them. gopherwatch could list the most recent prerelease, for automatic updating (with new policy), and we could list the prerelease on the admin page to select. especially useful if there is no tagged release at all yet.
- todo: do something for updating to release candidate go toolchains.
- todo: do something for finding new major versions. for goproxy, we could try requesting $modpath/v<num+1>, and gopherwatch dns could be changed (possibly new endpoint) to return newer major versions.
- todo: make it possible to detect new patch versions for multiple minor versions with gopherwatch dns. it currently returns only a single latest version.
- todo: consider making this installable as a service on windows.
- todo: consider adding a config option to indicate that a usr1 or usr2 to the service will cause it to re-exec itself for restartless updates. but how will we check that the signal was actually handled? (we don't?). do applications use other mechanisms? (custom ones, like writing to a unix domain socket ctl file, or http request)
- todo: consider implementing a privsep mode, where we are started as root, do most code as unprivileged user, only use root for putting the binary in place.
- todo: find more about standardized (sementic) versioning for applications (as opposed to libraries). major/minor/patch releases, updates for security issues, bugfixes, (incompatible) updates that require operator intervention, new features.
*/

/*
Files we use:
- ys/
	- ysco.conf, config file.
	- password.txt, default file for admin web interface .
	- scheduled.txt, lines with scheduled updates.
	- pause.txt, only present if we aren't currently automatically updating, e.g. after an error during an update.
	- old-binaries-svc.txt, old binaries for the service that we will remove on the next update.
	- old-binaries-self.txt, for binaries for ysco itself.
	- gobuildverifiercache/..., transparency log files, for downloading binaries.
*/

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"sync"

	"github.com/mjl-/sconf"

	"github.com/mjl-/ysco/internal/sumdb"
)

// Transparency log client for gobuild, for downloading binaries.
var tlog struct {
	ops *clientOps // Safe for use without lock.

	sync.Mutex
	client *sumdb.Client
}

func xcheckf(err error, format string, args ...any) {
	if err != nil {
		slog.Error(fmt.Sprintf(format, args...), "err", err)
		os.Exit(1)
	}
}

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ysco run [flags] ...")
		fmt.Fprintln(os.Stderr, "       ysco init vcshub.example/mod/cmd/ex")
		fmt.Fprintln(os.Stderr, "       ysco config >example.conf")
		fmt.Fprintln(os.Stderr, "       ysco configdefaults >defaults.conf")
		fmt.Fprintln(os.Stderr, "       ysco testconfig < ys/ysco.conf")
		fmt.Fprintln(os.Stderr, "       ysco licenses")
		fmt.Fprintln(os.Stderr, "       ysco version")
		flag.PrintDefaults()
		os.Exit(3)
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
	}

	cmd, args := args[0], args[1:]
	switch cmd {
	case "run":
		cmdRun(args)

	case "init":
		cmdInit(args)

	case "config":
		err := sconf.Describe(os.Stdout, config)
		xcheckf(err, "writing config")

	case "configdefaults":
		err := sconf.Describe(os.Stdout, defaults)
		xcheckf(err, "writing defaults")

	case "testconfig":
		var cfg Config
		err := parseConfigReader(os.Stdin, &cfg)
		xcheckf(err, "parsing config")

	case "licenses":
		licensesWrite(os.Stdout)

	case "version":
		fmt.Printf("ysco %s %s %s/%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	default:
		flag.Usage()
	}
}
