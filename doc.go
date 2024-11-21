// NOTE: generated from gendoc.sh

/*
Command ysco starts a Go binary, monitors for new versions of the module or the
Go toolchain in the Go module proxy and/or sum database, and can download
(verified through a transparency log) and install (according to a configured
schedule) new binaries for new module/toolchain versions. Both for the service
and itself.

Ysco works with applications that don't need cgo, and are self-contained (e.g.
use "embed" instead of requiring external files), and for which the source code
is available through the Go module proxy (though you can run your own Go module
proxy, Go sum database and gobuild instance with access to private code).

# Example

To start using ysco, first run "ysco init" with a Go application package path
as parameter. That writes a config file "./ys/ysco.conf", writes a password for
the admin interface to "./ys/password.txt", downloads a binary for the latest
version/goversion of the application from the gobuilds.org service, creates
short symlinks to the application binary and the ysco binary and finally prints
the command to run.

For example, to initialize for application github.com/mjl-/moxtools using an
ysco binary downloaded from
https://beta.gobuilds.org/github.com/mjl-/ysco@latest/linux-amd64-latest-stripped/:

	$ ./ysco-v0.1.0-go1.23.3 init github.com/mjl-/moxtools
	downloading github.com/mjl-/moxtools@v0.0.5/...
	initialized ys/, created symlinks ysco and moxtools, admin interface will be at http://admin:0jv9oQmWe34i@localhost:1234/ after starting:
	./ysco run -addr localhost:1234 ./moxtools #[flags]

Then we start:

	$ ./ysco run -addr localhost:1234 ./moxtools
	level=INFO msg="ysco starting" ysco="" version=v0.1.0/go1.23.3 svc=github.com/mjl-/moxtools svcversion=v0.0.5/go1.23.3 adminaddr=localhost:1234 metricsaddr=localhost:1234 goos=linux goarch=amd64
	l=print m="serving" pkg=moxtools listen=:8080 listenmetrics=:8081 hostname=x1 version=v0.0.5 goversion=go1.23.3 goos=linux goarch=amd64

# Mode of operation

Ysco will start the service ("./app" in the example above) with its flags,
forwards signals (intr, term, hup, usr1, usr2), and exits when the command
exits. Use a supervisor system, like systemd on Linux or rc.d scripts on BSDs
to restart ysco.

At startup ysco reads the module/package path from "./app" and starts looking
for updates for the module and Go toolchains in the background, and also for
updates for ysco itself. When ready to update, ysco downloads a new binary,
replaces "./app" (or "./ysco" when updating itself), and restarts the service
(or execs itself, for updates without restarts). If the new "./app" exits
within 5 seconds, the update is rolled back.

It is recommended to make "./ysco" and "./app" symlinks to specific versions,
e.g. "ysco-v0.0.1-go1.23.2". Ysco will then also create such symlinks, making
it easy to see which is the current version from command-line tools like "ls".

When updating, the previous binary is kept in the file system, but older
binaries are automatically cleaned up.

# Checking for updates

Ysco periodically checks for updates, both of the monitored service, and of
ysco itself. By default, it will first look in GopherWatch.org DNS (low overhead,
only returns the latest version), and will fall back to querying the Go module
proxy (higher overhead, returns all versions) in case of errors. The
GopherWatch.org DNS is DNSSEC-protected, consider installing/using a
DNSSEC-verifying resolver such as unbound.

# Downloading binaries

Ysco automatically retrieves a binary through the gobuilds.org service
(gobuild).  Gobuild retrieves source code from the Go module proxy, verified
through the Go sum database, and builds a binary for any Go
toolchain/OS/architecture.  The hash of the binary is added to the gobuild
transparency log (similar to the Go sum database), to build trust in its
correct operation.

Gobuild only builds applications that can be cross-compiled deterministically
(leading to the same bytes/hash) with only the Go toolchain, i.e. with
CGO_ENABLED=0. Only binaries that include all required assets (with "embed")
can be successfully installed.

# Update policy

When a new module version or toolchain is published, discovered by ysco and
matches the configured policy, an update is scheduled.

For new module versions, by default only patch releases are automatically
installed. Ysco can also be configured to automatically update to new minor
versions of modules.

For new Go toolchains, by default new patch releases will cause an update to be
installed. But if a new module version is published, the latest Go toolchain is
used, under the assumption that a new release was tested with the latest Go
release. Also, if a new Go toolchain was released, and the currently used
toolchain is no longer supported, an update using the latest "previous" Go
toolchain is installed. This is the "follow" policy. The "supported" mode is
similar, but does not update to the latest Go toolchain version when a new
module version is discovered.

The "manual" policy can be used for single-click manual updating.

# Update schedule

When a new module or toolchain version is discovered, and it matched the
configured policy, a new update is scheduled. You can configure a schedule with
days/hours during which updates should be installed, e.g. during working hours,
or in evenings or weekends. This should prevent botched updates from requiring
your attention at inconvenient hours. By default, updates are scheduled with a
24 hour delay after discovery.

# Web interface and metrics

Ysco can optionally be started with an admin web interface, both to see the
current module/Go versions, and to manually trigger an update. Endpoints:

  - / for an HTML view of the current versions and state like scheduled updates,
    with forms to trigger updates.
  - /update, for HTTP POST with form keys "which" ("self" or "svc"), "version"
    (e.g. "v0.1.2"), "goversion" (e.g. "go1.23.2").
  - /notify, HTTP POST, body currently ignored, no authentication, to be used for
    webhooks (e.g.  a gopherwatch.org webhook) to trigger checking for updates.
  - /notifytoolchain, like /notify, but to indicate a new Go toolchain is
    available.

Prometheus metrics can also be exported. Failure to install updates can be
discovered through the metrics.

# Bugs

Ysco does not automatically discover new major versions of modules (related to
module paths ending with /v<major> for versions >= 2).

Ysco relies on the Go sum database to discover new versions. New module
versions must be fetched through the Go module proxy once to get added to the
Go sum database. Running "go install <module>@latest" should be enough.

The GopherWatch DNS service currently only returns a single minor version for a
module. If an application has multiple maintained minor versions, only new
minor versions are discovered.

# Usage "ysco"

	usage: ysco run [flags] ...
	       ysco init vcshub.example/mod/cmd/ex
	       ysco config >example.conf
	       ysco configdefaults >defaults.conf
	       ysco testconfig < ys/ysco.conf
	       ysco licenses
	       ysco version

# Usage "ysco run"

	usage: ysco run [flags] cmd ...
	  -addr string
	    	address to webserve admin and metrics interfaces; cannot be used together with adminaddr and metricsaddr
	  -adminaddr string
	    	if non-empty, address to serve only admin webserver; also see -addr; see -adminauthfile for requiring authentication
	  -dir string
	    	directory with config file, state files and transparency log cache (default "ys")
	  -groups string
	    	comma-separated groups/gids to run command as, overriding additional groups of system user
	  -metricsaddr string
	    	if non-empty, address to serve only metrics webserver; also see -addr
	  -user string
	    	username/uid to run command as

# Example config with defaults

Built-in defaults that are used for missing/empty fields in the active
configuration file. As generated by "ysco configdefaults":

	# NOTE: Indenting in this config file can be done with tabs only, not spaces.
	#
	# Values 'debug', 'info', 'warn', 'error'. Default info.
	LogLevel:

	# Path to file with password to use for HTTP basic authentication (username is
	# always 'admin').
	AuthFile:

	# Settings for how to check for updates. (optional)
	Monitor:

		# Methods to use for finding updates. First successful method is used. Values
		# 'dns', 'goproxy'. If empty, 'dns' and 'goproxy' are used. (optional)
		Methods:
			- dns
			- goproxy

		# Gopherwatch DNS base hostname to use for looking up updates. If empty,
		# l.gopherwatch.org is used. (optional)
		DNS: l.gopherwatch.org

		# Base URL for Go module proxy. If empty, https://proxy.golang.org/cached-only/ is
		# used. (optional)
		GoProxy: https://proxy.golang.org/cached-only/

		# If set, Go module proxy base URL to use for finding updates of Go toolchains.
		# (optional)
		GoProxyToolchain:

		# Wait time until first check for updates after starting up. (optional)
		Delay: 1m0s

		# Time between checks for updates. (optional)
		Interval: 24h0m0s

	# Policies for automated/manual updates. (optional)
	Policy:

		# Policy for updating when a new version of the monitored service is discovered.
		# (optional)
		Service: patch

		# Policy for updating when a new version of ysco is discovered. (optional)
		Self: patch

		# Policy for updating the monitored service when a new Go toolchain is discovered.
		# (optional)
		ServiceToolchain: follow

		# Policy for updating ysco when a new Go toolchain is discovered. (optional)
		SelfToolchain: follow

	# Settings for updating. (optional)
	Update:

		# Minimum wait time between discovery of update and rolling out the update.
		# (optional)
		Delay: 72h0m0s

		# When to do updates, e.g. during working hours, or only evenings or weekends.
		# Specified as a list of periods, each entry with days and/or hours (no minute
		# precision) separated by a space. Days and days are comma-separated, with the
		# values a single day or an inclusive range. Hours always have to be specified as
		# a range. Example: 'tu-th,sa' (any hour on these days), or '18-21' (any day
		# between 18h and 21h), or 'mo-fr 9-17'. Updates are scheduled in the first
		# available hour, taking backoff and jitter into account. If empty, all days/hours
		# are allowed. (optional)
		Schedule:
			-

		# Max random time to wait for performing the update within the scheduled hour.
		# (optional)
		Jitter: 1h0m0s

		# Cycle through all discovered updates instead of cancelling a pending update when
		# another new update is discovered. (optional)
		All: false

	# Settings for the gobuilds.org service. (optional)
	Gobuild:

		# For verifying the gobuild transparency log.
		VerifierKey: beta.gobuilds.org+3979319f+AReBl47t6/Zl24/pmarcKhJtsfAU2c1F5Wtu4hrOgOQQ

		# Base URL for gobuild service. Derived from VerifierKey by default. (optional)
		BaseURL:

	# Links to show on admin page for convenience, e.g. to the service that is being
	# run. (optional)
	Links:
		-

			# Link shown on admin page, clickable.
			URL:

			# Text to show next to link. (optional)
			Text:

	# Additional configuration for the service process. (optional)
	Process:

		# Capabilities to preserve in the service process, either by name or number, e.g.
		# CAP_NET_BIND_SERVICE or 0xa. During fork and exec that sets a new user/group id,
		# capabilities are dropped by default. (optional)
		AmbientCapabilities:
			-
*/
package main
