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

To use, just put "ysco run" in front of the regular command-line used to start
the service. For example:

	./ysco run [yscoflags] ./app [appflags]

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

See ysco help output for its command-line flags.

# Checking for updates

Ysco periodically checks for updates, both of the monitored service, and of
ysco itself. By default, it will first look in GopherWatch.org DNS (low overhead,
only return the latest version), and will fall back to querying the Go module
proxy (higher overhead, returns all versions) in case of errors. The
GopherWatch.org DNS is DNSSEC-protected, consider installing/using a
DNSSEC-verifying resolver.

# Downloading binaries

Ysco automatically retrieves a binary for a module through the gobuild service.
Gobuild will retrieve source code from the Go module proxy, verified through
the Go sum database, and build a binary for any Go toolchain/OS/architecture.
The hash of the binary is added to the gobuild transparency log (similar to the
Go sum database), to build trust in its correct operation.

The gobuild service only builds applications that can be cross-compiled
deterministically (leading to the same bytes/hash) with only the Go toolchain,
i.e. with CGO_ENABLED=0. Only binaries that include all require assets (with
"embed") can be successfully installed.

# Update policy

When a new module version or toolchain is published and discovered by ysco,
they are scheduled for installing if they match the configured policy.

For new module versions, by default only patch releases are automatically
installed.

For new Go toolchains, by default new patch releases will cause an update to be
installed. But if a new module version is published, the latest Go toolchain is
supposed, under the assumption that a new release was tested with the latest Go
releases. Also, if a new Go toolchain is installed, and the currently used
toolchain is no longer supported, an update using the latest "previous" Go
toolchain is installed. This is the "follow" policy. The "supported" mode is
similar, but does not update to the latest Go toolchain version when a new
module version is discovered.

Ysco can be configured to automatically update to new minor versions of
modules.

# Update schedule

Once a new module or toolchain version is discovered, and it matched the
configured policy, a new update will be scheduled. You can configure a schedule
with days/hours during which updates should be installed, e.g. during working
hours, or in evenings or weekends. This should prevent botched updates from
requiring your attention at inconvenient hours. By default, updates are
scheduled with a 24 hour delay after discovery.

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
Go sum database. A "go install <module>@latest" should be enough.

The GopherWatch DNS service currently only returns a single minor version for a
module. If an application has multiple maintained minor versions, only new
minor versions are discovered.

# Usage "ysco"

	usage: ysco run [flags] ...
	       ysco licenses
	       ysco version

# Usage "ysco run"

	usage: ysco run [flags] cmd ...
	  -adminaddr string
	    	address to serve admin webserver on if non-empty; see -adminauthfile for requiring authentication
	  -adminauthfile string
	    	file containing line of form 'user:password' for use with http basic auth for the non-webhook endpoints; if not specified, no authentication is enforced.
	  -cachedir string
	    	cache directory with transparency log cache and update state files (default "yscocache")
	  -gobuildverifier string
	    	gobuild verifier key and optionally url (default "beta.gobuilds.org+3979319f+AReBl47t6/Zl24/pmarcKhJtsfAU2c1F5Wtu4hrOgOQQ")
	  -groups string
	    	comma-separated groups/gids to run command as, overriding additional groups of system user
	  -loglevel value
	    	loglevel, one of error, warn, info, debug (default INFO)
	  -metricsaddr string
	    	address to serve metrics webserver on if non-empty (default "localhost:8524")
	  -monitor string
	    	mechanism to lookup new modules/toolchains, comma-separated, next method is attempted on failure, values: dns, goproxy (default "dns,goproxy")
	  -monitordelay duration
	    	time until starting to monitor for updates after startup (default 1m0s)
	  -monitordns string
	    	base hostname for gopherwatch dns module lookups (default "l.gopherwatch.org")
	  -monitorgoproxy string
	    	base url of a go module proxy for monitoring module updates through its list endpoint (default "https://proxy.golang.org/cached-only/")
	  -monitorgoproxytoolchain string
	    	if set, the go proxy base url to use for toolchain lookups
	  -monitorinterval duration
	    	interval between looking up modules to find updates (default 24h0m0s)
	  -policyself string
	    	policy for updating ysco: patch, minor, manual (default "patch")
	  -policyselftoolchain string
	    	policy for updating ysco: patch, minor, manual, supported, follow (default "follow")
	  -policysvc string
	    	policy for updating service: patch, minor, manual (default "patch")
	  -policysvctoolchain string
	    	policy for updating service: patch, minor, manual, supported, follow (default "follow")
	  -updatedelay duration
	    	delay between finding module update and updating (default 24h0m0s)
	  -updatejitter duration
	    	maximum random delay within the scheduled hour to delay (default 1h0m0s)
	  -updateschedule value
	    	schedule during which updates can be done: semicolon separated tokens with days and/or hours, each comma-separated of which each a single or dash-separated range; hours from 0-23, days from su-sa; examples: 'mo-fr 9-16' for during work days, 'mo-fr 18-22; sa,su 9-18' for workday evenings and weekends; updates are scheduled in the first available hour, taking backoff and jitter into account
	  -user string
	    	username/uid to run command as
*/
package main