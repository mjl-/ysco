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
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	xgoversion "go/version"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/sys/unix"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Command-line flags.
var ysDir string // For config, verifier cache and state files like pause.txt, scheduled.txt and old-binaries-{self,svc}.txt.
var addr string
var adminAddr string
var metricsAddr string
var username string // If set, we must be called as root and we'll start the process as this user. If group is not set explicitly, all groups of the user are set. If not a username, then interpreted as uid.
var groups string   // Only set this group (or comma-separated groups) when starting the process.

var logLevel slog.LevelVar
var cacheDir string // ysDir plus "gobuildverifiercache"

var cmdArgs []string // argv for starting service.

// Only meaningfull when username is set (was specified). Set once at startup.
var userID, groupID uint32
var groupIDs []uint32 // All groups, including primary group.

var updating struct {
	sync.Mutex

	// Whether we are still in an update. New updates will be rejected with an error.
	// Cleared 5 seconds after new process is started.
	busy bool

	// Time of start of updated process. Used to recognize quick failure after updating
	// the service, causing us to rollback.
	started time.Time

	// Whether we rolled back the last update. If so, we won't try to rollback
	// again on command failure.
	rolledback bool

	// Active service process, to forward signals to, and send sigterm to when updating.
	process *os.Process

	// If non-empty, we are not currently doing automatic updates due to earlier
	// failure to update. Cleared after successful (e.g. manual) update.
	pauseReason string

	// Current service & self build info, read from files.
	svcinfo  *debug.BuildInfo
	selfinfo *debug.BuildInfo

	// Of previous binary, set when doing an update, for rollback.
	svcinfoPrev       *debug.BuildInfo
	binaryPathPrevAbs string
}

var schedule struct {
	sync.Mutex

	// Fires when we can update.
	timer *time.Timer

	// Number of times we backed off. Each time we double number of hours delay (while
	// staying within update schedule. Cleared when we do a manual update and after
	// success.
	backoff int

	// All pending updates. When looking for next updates, we compare against the
	// latest (last) that we've already planned.
	updates []Update

	// Update currently planned for installing when timer expires, if any. Will
	// be checked again against schedule.updates when timer triggers.
	up *Update
}

// In-memory state of old-binaries-{self,svc}.txt. Read at startup, written
// whenever changes are made.
var oldBinaries struct {
	sync.Mutex
	Self []string
	Svc  []string
}

// For doing next periodic check for updates.
var monitorTimer *time.Timer

// execState is passed to the new ysco in an environment variable when exec'ing
// itself (as part of updating itself).
type execState struct {
	Pid            int       // Of the running managed service.
	Start          time.Time // Start time of the process.
	IsConfigChange bool      // Not for updating, but for config change.
	OldVersion     string    // Of ysco.
	OldGoVersion   string
	RequestFD      uintptr // If > 0, then write an HTTP response to this file.
	Redirect       bool    // Whether to respond on RequestFD with redirect 303 to / (or 200 ok).
}

func cmdRun(args []string) {
	flg := flag.NewFlagSet("ysco run", flag.ExitOnError)

	// NOTE: we cannot change existing cli flags in incompatible way: when ysco updates
	// itself with exec, it passes the same flags as it originally got (and they are
	// likely in some system supervisor service config file, so would come back after
	// the supervisor restarts ysco).

	flg.StringVar(&ysDir, "dir", "ys", "directory with config file, state files and transparency log cache")
	flg.StringVar(&username, "user", "", "username/uid to run command as")
	flg.StringVar(&groups, "groups", "", "comma-separated groups/gids to run command as, overriding additional groups of system user")
	flg.StringVar(&addr, "addr", "", "address to webserve admin and metrics interfaces; cannot be used together with adminaddr and metricsaddr")
	flg.StringVar(&adminAddr, "adminaddr", "", "if non-empty, address to serve only admin webserver; also see -addr; see -adminauthfile for requiring authentication")
	flg.StringVar(&metricsAddr, "metricsaddr", "", "if non-empty, address to serve only metrics webserver; also see -addr")

	cacheDir = filepath.Join(ysDir, "gobuildverifiercache")

	flg.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ysco run [flags] cmd ...")
		flg.PrintDefaults()
		os.Exit(3)
	}
	flg.Parse(args)
	cmdArgs = flg.Args()
	if len(cmdArgs) == 0 {
		flg.Usage()
	}

	if addr != "" && (adminAddr != "" || metricsAddr != "") {
		log.Printf("cannot use -addr with -adminaddr/-metricsaddr")
		flg.Usage()
	}
	if addr != "" {
		adminAddr = addr
		metricsAddr = addr
	}

	if username == "" && groups != "" {
		log.Fatalf("-groups requires -user")
	}
	if username != "" {
		if os.Getuid() != 0 {
			log.Fatalf("-user requires running as root")
		}

		var uidstr string
		u, err := user.Lookup(username)
		var unknownUser user.UnknownUserError
		if err != nil && !errors.As(err, &unknownUser) {
			log.Fatalf("looking up user: %v", err)
		}
		if err != nil {
			u, err = user.LookupId(username)
			if err != nil {
				uidstr = username
			} else {
				uidstr = u.Uid
			}
		} else {
			uidstr = u.Uid
		}
		id, err := strconv.ParseUint(uidstr, 10, 32)
		xcheckf(err, "finding user %q and parsing uid %q", username, uidstr)
		userID = uint32(id)
		if u != nil {
			gid, err := strconv.ParseUint(u.Gid, 10, 32)
			xcheckf(err, "parsing gid for user")
			groupID = uint32(gid)
		}
		if groups == "" {
			if u == nil {
				log.Fatalf("numeric uid without system user requires -groups")
			}
			gidstrs, err := u.GroupIds()
			xcheckf(err, "get group ids for user")
			for _, gidstr := range gidstrs {
				gid, err := strconv.ParseUint(gidstr, 10, 32)
				xcheckf(err, "parsing gid %q", gidstr)
				groupIDs = append(groupIDs, uint32(gid))
			}
		} else {
			for i, gs := range strings.Split(groups, ",") {
				var gidstr string
				var unknownGroup user.UnknownGroupError
				g, err := user.LookupGroup(gs)
				if err != nil && !errors.As(err, &unknownGroup) {
					log.Fatalf("looking up group %q: %v", gs, err)
				} else if err != nil {
					gidstr = gs
				} else {
					gidstr = g.Gid
				}
				gid, err := strconv.ParseUint(gidstr, 10, 32)
				if err != nil {
					log.Fatalf("cannot find group %q and cannot parse as gid", gs)
				}
				// If we don't have a system user, first group in list is the primary group.
				if u == nil && i == 0 {
					groupID = uint32(gid)
				}
				groupIDs = append(groupIDs, uint32(gid))
			}
		}
	}

	err := parseConfig(filepath.Join(ysDir, "ysco.conf"), &config)
	xcheckf(err, "parsing config")

	err = logLevel.UnmarshalText([]byte(config.LogLevel))
	xcheckf(err, "unmarshalling log level")

	verifierCacheDir := filepath.Join(ysDir, "gobuildverifiercache")
	os.MkdirAll(verifierCacheDir, 0700)
	tlog.client, tlog.ops, err = newClient(fallback(config.Gobuild.VerifierKey, defaults.Gobuild.VerifierKey), fallback(config.Gobuild.BaseURL, defaults.Gobuild.BaseURL), verifierCacheDir)
	xcheckf(err, "new tlog client")

	if !filepath.IsAbs(cmdArgs[0]) && !strings.HasPrefix(cmdArgs[0], "./") && !strings.HasPrefix(cmdArgs[0], "../") {
		log.Fatalf("command path must be explicit path (absolute, or relative from current dir)")
	}

	slogOpts := slog.HandlerOptions{
		Level: &logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == "time" {
				return slog.Attr{}
			}
			return a
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slogOpts)).With("ysco", "")
	slog.SetDefault(logger)

	if fi, err := os.Lstat(cmdArgs[0]); err != nil {
		log.Fatalf("lstat %s to check for symlink: %v", cmdArgs[0], err)
	} else if fi.Mode()&fs.ModeSymlink == 0 {
		slog.Warn("tip: make the managed service binary a symlink for to more easily see the current version")
	}

	if fi, err := os.Lstat(os.Args[0]); err != nil {
		log.Fatalf("lstat %s to check for symlink: %v (try calling as full path)", os.Args[0], err)
	} else if fi.Mode()&fs.ModeSymlink == 0 {
		slog.Warn("tip: making ysco a symlink makes it possible to update it without interrupting the managed service")
	}

	if username != "" {
		// Check that user/groups have permission to execute command.
		abspath, err := filepath.Abs(cmdArgs[0])
		xcheckf(err, "absolute path for binary")

		paths := []string{abspath}
		dir := abspath
		for {
			ndir := filepath.Dir(dir)
			if dir == ndir {
				break
			}
			paths = append(paths, ndir)
			dir = ndir
		}
		slices.Reverse(paths)

		for _, p := range paths {
			has, err := hasModeBit(p, 0b001, userID, groupIDs)
			xcheckf(err, "checking permissions on %s", p)
			if !has {
				log.Fatalf("command not executable for user/groups, no x-bit for path %s", p)
			}
		}

		// Warn if user has write permission anywhere in the directory hierarchy.
		for _, p := range paths {
			has, err := hasModeBit(p, 0b010, userID, groupIDs)
			if err != nil || has {
				if err == nil {
					err = fmt.Errorf("user/groups has write permissions")
				}
				slog.Warn("checking for write permissions for user/groups", "path", p, "err", err)
			}
		}
	}

	// Read module & version from binary.
	svcinfo, err := buildinfo.ReadFile(cmdArgs[0])
	xcheckf(err, "reading buildinfo from command")
	var ok bool
	selfinfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatalf("could not get buildinfo for own binary")
	}
	updating.svcinfo = svcinfo
	updating.selfinfo = selfinfo

	slog.Info("ysco starting", "version", selfinfo.Main.Version+"/"+selfinfo.GoVersion, "svc", svcinfo.Path, "svcversion", svcinfo.Main.Version+"/"+svcinfo.GoVersion, "adminaddr", adminAddr, "metricsaddr", metricsAddr, "goos", runtime.GOOS, "goarch", runtime.GOARCH)
	slog.Debug("service info", "modpath", svcinfo.Main.Path, "pkgdir", packageDir(svcinfo), "version", svcinfo.Main.Version, "goversion", svcinfo.GoVersion)
	slog.Debug("self info", "modpath", selfinfo.Main.Path, "pkgdir", packageDir(selfinfo), "version", selfinfo.Main.Version, "goversion", selfinfo.GoVersion)
	slog.Debug("starting service", "cmd", cmdArgs)

	metricSelfVersion.WithLabelValues(selfinfo.Main.Version).Set(1)
	metricSvcVersion.WithLabelValues(svcinfo.Main.Version).Set(1)
	metricSvcGoVersion.WithLabelValues(svcinfo.GoVersion).Set(1)
	metricSvcModPath.WithLabelValues(svcinfo.Main.Path).Set(1)

	if (svcinfo.Main.Version == "" || svcinfo.Main.Version == "(devel)") && fallback(config.Policy.Service, defaults.Policy.Service) != VersionManual {
		slog.Warn("version of module unknown, cannot compare versions for updates")
	}

	if buf, err := os.ReadFile(filepath.Join(cacheDir, "pause.txt")); err == nil {
		updating.pauseReason = string(buf)
		if updating.pauseReason == "" {
			updating.pauseReason = "(no reason)"
		}
		metricUpdatesPaused.Set(1)
		slog.Warn("automatic updates paused due to existence of pause.txt", "reason", updating.pauseReason)
	}

	oldBinaries.Self, err = listOldBinaries("old-binaries-self.txt")
	xcheckf(err, "reading old-binaries-self.txt")
	oldBinaries.Svc, err = listOldBinaries("old-binaries-svc.txt")
	xcheckf(err, "reading old-binaries-svc.txt")

	// Possibly a shared handler for admin & metrics.
	adminHandler := http.NewServeMux()
	metricsHandler := http.NewServeMux()
	if adminAddr != "" && adminAddr == metricsAddr {
		metricsHandler = adminHandler
	}

	adminHandler.HandleFunc("GET /favicon.ico", handleFavicon)
	adminHandler.HandleFunc("GET /{$}", handleIndexGet)
	adminHandler.HandleFunc("POST /{$}", handleIndexPost)
	adminHandler.HandleFunc("GET /json", handleJSONGet)
	adminHandler.HandleFunc("POST /notify", handleNotify)
	adminHandler.HandleFunc("POST /notifytoolchain", handleNotifyToolchain)
	adminHandler.HandleFunc("POST /update", handleUpdate)

	metricsHandler.Handle("GET /metrics", promhttp.Handler())

	if adminAddr != "" && adminAddr == metricsAddr {
		// Single web server for both admin and metrics.
		conn, err := net.Listen("tcp", adminAddr)
		xcheckf(err, "listen for webserver")

		go func() {
			err := http.Serve(conn, adminHandler)
			xcheckf(err, "serve webserver")
		}()
	} else {
		if adminAddr != "" {
			adminconn, err := net.Listen("tcp", adminAddr)
			xcheckf(err, "listen for admin webserver")

			go func() {
				err := http.Serve(adminconn, adminHandler)
				xcheckf(err, "serve admin webserver")
			}()
		}

		if metricsAddr != "" {
			// For separate metrics webserver, redirect user to metrics.
			metricsHandler.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/metrics", http.StatusFound)
			})

			metricsconn, err := net.Listen("tcp", metricsAddr)
			xcheckf(err, "listening for metrics webserver")

			go func() {
				err := http.Serve(metricsconn, metricsHandler)
				xcheckf(err, "serving metrics webserver")
			}()
		}
	}

	if l, err := readScheduledTxt(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		xcheckf(err, "read scheduled.txt")
	} else {
		schedule.updates = l
	}
	schedule.timer = time.NewTimer(0)
	schedule.timer.Stop()
	reschedule()

	signalc := make(chan os.Signal, 1)
	signal.Notify(signalc, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	if statestr := os.Getenv("_YSCO_EXEC"); statestr != "" {
		pickupProcess(statestr)
	} else {
		startProcess()
	}

	// Wait for service process to finish, and send result to main loop (below).
	p := updating.process
	go func() {
		state, err := p.Wait()
		waitc <- waitResult{state, err}
	}()

	// Start monitoring loop.
	var monitorc <-chan time.Time
	if len(fallbackList(config.Monitor.Methods, defaults.Monitor.Methods)) > 0 {
		monitorTimer = time.NewTimer(fallback(config.Monitor.Delay, defaults.Monitor.Delay))
		monitorc = monitorTimer.C
	}

	for {
		select {
		case <-monitorc:
			slog.Debug("looking for new module version or toolchain version")
			monitorOne()
			monitorTimer.Reset(fallback(config.Monitor.Interval, defaults.Monitor.Interval))

		case sig := <-signalc:
			// Pass signals on to the service process.
			slog.Debug("signal for service", "signal", sig)
			updating.Lock()
			err := updating.process.Signal(sig)
			if err != nil {
				slog.Error("sending signal to process", "sig", sig, "err", err)
			}
			updating.Unlock()

		// We are ready to install an update according to our scheduled updates.
		case <-schedule.timer.C:
			updateUpcoming()

		// When the service command exits, we get its process state. If we are updating, we
		// restart the service, now with the new binary. If we weren't updating, we just
		// quit and let whoever supervises us restart us.
		case result := <-waitc:
			state, err := result.state, result.err
			if state != nil {
				usage := state.SysUsage()
				ru, ok := usage.(*syscall.Rusage)
				if !ok {
					slog.Error("rusage after command is not *syscall.Rusage but %T", usage)
				} else {
					updating.Lock()
					start := updating.started
					updating.Unlock()
					slog.Debug("service finished, resources used",
						"duration", time.Since(start),
						"utime", ru.Utime,
						"stime", ru.Stime,
						"maxrss", ru.Maxrss,
						"ixrss", ru.Ixrss,
						"idrss", ru.Idrss,
						"isrss", ru.Isrss,
						"minflt", ru.Minflt,
						"majflt", ru.Majflt,
						"nswap", ru.Nswap,
						"inblock", ru.Inblock,
						"oublock", ru.Oublock,
						"msgnd", ru.Msgsnd,
						"msgrcv", ru.Msgrcv,
						"nsignals", ru.Nsignals,
						"nvcsw", ru.Nvcsw,
						"nivcsw", ru.Nivcsw,
						"err", err,
					)
				}
			} else {
				slog.Debug("command finished", "err", err)
			}
			updating.Lock()
			if updating.busy {
				// todo: recognize if the exit was actually due to the update?
				var xerr error
				updating.svcinfo, xerr = buildinfo.ReadFile(cmdArgs[0])
				xcheckf(xerr, "reading newbuildinfo from command")

				slog.Debug("updating, command finished, starting again", "err", err)
				updating.started = time.Now()
				updating.rolledback = false

				startProcess()
				p := updating.process
				updating.Unlock()

				// After 5 seconds, mark as no longer updating and reschedule for possible next
				// update.
				go func() {
					time.Sleep(5 * time.Second)
					slog.Debug("clearing busy after 5s")
					updating.Lock()
					updating.busy = false
					updating.Unlock()
					slog.Debug("busy cleared")
				}()

				go func() {
					state, err := p.Wait()
					waitc <- waitResult{state, err}
				}()

				continue
			}
			updating.Unlock()
			if err != nil {
				// handleExit either quits or starts the service again, possibly after a rollback.
				handleExit("wait", err)
			} else {
				slog.Info("service process finished without error, quitting")
				os.Exit(0)
			}
		}
	}
}

// reschedule writes schedule.txt and resets schedule.timer if needed.
//
// schedule lock must be held by caller.
func reschedule() {
	if err := writeScheduledTxt(schedule.updates); err != nil {
		slog.Error("update scheduled.txt", "err", err)
	}

	var nself, nsvc float64
	for _, l := range schedule.updates {
		if l.Which == Self {
			nself++
		} else {
			nsvc++
		}
	}
	metricSelfUpdateScheduled.Set(nself)
	metricSvcUpdateScheduled.Set(nsvc)

	updating.Lock()
	paused := updating.pauseReason != ""
	updating.Unlock()

	var up *Update
	if i := updateUpcomingFindIndex(); i >= 0 {
		up = &schedule.updates[i]
	}

	if !paused && up != nil && (schedule.up == nil || up.Time.Before(schedule.up.Time)) {
		schedule.up = up

		// Take backoff into account, if any.
		uptm := up.Time
		var backoff time.Duration
		for i := range schedule.backoff {
			if i == 0 {
				backoff = time.Hour
			} else {
				backoff *= 2
			}
		}
		if backoff > 0 {
			uptm = uptm.Add(backoff)
			// We need to find the next slot we can do the update.
			var sched Schedule = fallbackList(config.Update.schedule, defaults.Update.schedule)
			uptm = sched.Next(uptm)
		}
		d := time.Until(uptm)

		jitter := time.Duration(secretRand.Int64N(int64(fallback(config.Update.Jitter, defaults.Update.Jitter)/time.Second))) * time.Second
		d += jitter
		d = max(0, d)
		tm := uptm.Add(d)
		if tm.After(uptm.Add(time.Hour)) {
			tm = uptm.Add(time.Hour)
		}
		d = max(0, time.Until(tm))

		slog.Info("next update scheduled", "time", uptm, "wait", d, "version", schedule.up.Version, "goversion", schedule.up.GoVersion, "modpath", schedule.up.ModPath, "pkgdir", schedule.up.PkgDir, "which", schedule.up.Which)
		schedule.timer.Stop()
		schedule.timer.Reset(d)
	} else if up == nil && schedule.up != nil {
		slog.Info("canceling scheduled update")
		schedule.timer.Stop()
		schedule.up = nil
	}
}

func updateUpcomingFindIndex() int {
	var up *Update
	var index = -1
	for i, p := range schedule.updates {
		if up == nil || !p.Time.After(up.Time) {
			up = &schedule.updates[i]
			index = i
		}
	}
	return index
}

// updateUpcoming checks if the upcoming update is still current, and starts a
// goroutine to start the update.
func updateUpcoming() {
	schedule.Lock()
	up := schedule.up
	curindex := updateUpcomingFindIndex()
	if up == nil || curindex < 0 || schedule.updates[curindex] != *up {
		slog.Info("schedule update not current anymore, rescheduling")
		reschedule()
		schedule.Unlock()
		return
	}
	schedule.Unlock()

	go func() {
		xup := *up
		// note: if up.Which is Self, update execs itself and never returns.
		err := update(up.Which, up.ModPath, up.Version, up.GoVersion, &xup, nil, false, false)
		if err != nil {
			slog.Error("updating failed", "err", err)
		}

		schedule.Lock()
		curindex = updateUpcomingFindIndex()
		if curindex >= 0 {
			copy(schedule.updates[curindex:], schedule.updates[curindex+1:])
			schedule.updates = schedule.updates[:len(schedule.updates)-1]
		}
		schedule.up = nil
		reschedule()
		schedule.Unlock()
	}()
}

type waitResult struct {
	state *os.ProcessState
	err   error
}

var waitc = make(chan waitResult)

func pickupProcess(statestr string) {
	slog.Debug("picking up existing process after exec", "state", statestr)

	var es execState
	err := json.Unmarshal([]byte(statestr), &es)
	xcheckf(err, "unmarshal execstate")

	err = os.Unsetenv("_YSCO_EXEC")
	xcheckf(err, "clearing _YSCO_EXEC")

	updating.process, err = os.FindProcess(es.Pid)
	xcheckf(err, "finding process by pid")
	updating.started = es.Start

	slog.Info("ysco back after exec", "prev", es.OldVersion, "prevgo", es.OldGoVersion, "new", updating.selfinfo.Main.Version, "newgo", updating.selfinfo.GoVersion, "isconfigchange", es.IsConfigChange)

	// Remove any pause.txt file that would prevent future automatic updates.
	if !es.IsConfigChange {
		os.Remove(filepath.Join(cacheDir, "pause.txt"))
		updating.Lock()
		updating.pauseReason = ""
		metricUpdatesPaused.Set(0)
		updating.Unlock()
	}

	if es.RequestFD > 0 {
		f := os.NewFile(es.RequestFD, "requestfd")
		if f == nil {
			slog.Error("cannot make file from request fd")
			return
		}

		// todo: should we know about http/1 vs http/2?
		body := fmt.Sprintf("updated self from %s %s to %s %s\n", es.OldVersion, es.OldGoVersion, updating.selfinfo.Main.Version, updating.selfinfo.GoVersion)
		resp := http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			Header:        http.Header{"Content-Type": []string{"text/plain"}},
			ContentLength: int64(len(body)),
			Body:          io.NopCloser(strings.NewReader(body)),
			Close:         true,
		}
		if es.Redirect {
			resp.StatusCode = http.StatusSeeOther
			resp.Header.Add("Location", "/")
		}
		err := resp.Write(f)
		if err != nil {
			slog.Error("write response after exec", "err", err)
		}
		if err := f.Close(); err != nil {
			slog.Error("closing request fd", "err", err)
		}
	}
}

func startProcess() {
	slog.Debug("starting command")

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = sysProcAttr()
	if username != "" {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid:    userID,
			Gid:    groupID,
			Groups: groupIDs,
		}
	}
	// Not setting Pdeathsig, it seems to kill the process when we exec ourselves.

	t0 := time.Now()
	err := cmd.Start()
	if err != nil {
		// handleExit either quits or starts the service again, possibly after a rollback.
		handleExit("start", err)
		return
	}
	updating.started = t0
	updating.process = cmd.Process
	if username != "" {
		slog.Debug("command started", "uid", userID, "gids", groupIDs)
	} else {
		slog.Debug("command started")
	}
}

func handleExit(when string, err error) {
	slog.Error("command exited with error", "err", err, "when", when)
	code := 1
	if xerr, ok := err.(*exec.ExitError); ok {
		code = xerr.ExitCode()
	}

	updating.Lock()

	if time.Since(updating.started) >= 5*time.Second {
		slog.Error("service exited, so will we", "exitcode", code)
		os.Exit(code)
	}
	if updating.rolledback {
		slog.Error("command exited within 5s after rollback, giving up", "err", err, "exitcode", code)
		os.Exit(code)
	}
	updating.rolledback = true

	// Creating pause.txt so we don't try any more automatic updates.
	binName := fmt.Sprintf("%s-%s-%s", path.Base(updating.svcinfo.Main.Path), updating.svcinfo.Main.Version, updating.svcinfo.GoVersion)
	updating.pauseReason = fmt.Sprintf("binary %s exited within 5s: %v\n", binName, err)
	if err := os.WriteFile(filepath.Join(cacheDir, "pause.txt"), []byte(updating.pauseReason), 0640); err != nil {
		slog.Error("writing pause.txt failed", "err", err)
	}

	slog.Error("command exited within 5s after update, will attempt to roll back, and pausing further automatic updates", "err", err)
	metricSvcUpdateRollback.Inc()
	metricUpdatesPaused.Set(1)
	if err := updateRollback(); err != nil {
		slog.Error("rollback after failed update failed, giving up", "err", err)
		os.Exit(code)
	}
	slog.Warn("rolled back after failed update, restarting", "err", err)

	startProcess()
	p := updating.process
	updating.Unlock()
	go func() {
		state, err := p.Wait()
		waitc <- waitResult{state, err}
	}()
}

func scheduledCancel(which Which) {
	schedule.Lock()
	defer schedule.Unlock()

	schedule.backoff = 0

	var l []Update
	for _, u := range schedule.updates {
		if u.Which != which {
			l = append(l, u)
		}
	}
	schedule.updates = l
	reschedule()
}

func latest(which Which, info *debug.BuildInfo) (version, goversion string) {
	schedule.Lock()
	defer schedule.Unlock()

	for i := len(schedule.updates) - 1; i >= 0; i-- {
		if schedule.updates[i].Which == which {
			return schedule.updates[i].Version, schedule.updates[i].GoVersion
		}
	}
	return info.Main.Version, info.GoVersion
}

// monitorOne checks for updates once.
func monitorOne() (rerr error) {
	// todo: lookup in goroutines?

	if len(fallbackList(config.Monitor.Methods, defaults.Monitor.Methods)) == 0 {
		return nil
	}

	tc, err := lookupToolchainVersions(slog.Default())
	if err != nil {
		slog.Error("looking up toolchain version", "err", err)
		rerr = err
		return
	} else {
		slog.Debug("latest toolchains", "toolchains", tc)
	}

	// We first lookup & schedule for the managed module. Then for ysco. If both get an
	// update scheduled, this causes the managed service to be updated first. That's
	// good, because if something is terribly wrong with the updates, the managed
	// service gets rolled back. We cannot roll back when exec-ing ysco.

	updating.Lock()
	svcinfo := updating.svcinfo
	selfinfo := updating.selfinfo
	updating.Unlock()

	// Update metrics for available go versions.
	metricSvcGoVersionAvailable.Set(boolGauge(xgoversion.Compare(tc.Cur, svcinfo.GoVersion) > 0))
	metricSelfGoVersionAvailable.Set(boolGauge(xgoversion.Compare(tc.Cur, selfinfo.GoVersion) > 0))

	polsvc := fallback(config.Policy.Service, defaults.Policy.Service)
	polsvctc := fallback(config.Policy.ServiceToolchain, defaults.Policy.ServiceToolchain)
	if versAvail, upAvail, err := scheduleUpdate(Svc, svcinfo, polsvc, polsvctc, tc); err != nil {
		slog.Error("looking for updates for service", "err", err)
		rerr = err
	} else {
		metricSvcVersionAvailable.Set(boolGauge(versAvail))
		metricSvcUpdateAvailable.Set(boolGauge(upAvail))
	}

	polself := fallback(config.Policy.Self, defaults.Policy.Self)
	polselftc := fallback(config.Policy.SelfToolchain, defaults.Policy.SelfToolchain)
	if versAvail, upAvail, err := scheduleUpdate(Self, selfinfo, polself, polselftc, tc); err != nil {
		slog.Error("looking for updates for self", "err", err)
		rerr = err
	} else {
		metricSelfVersionAvailable.Set(boolGauge(versAvail))
		metricSelfUpdateAvailable.Set(boolGauge(upAvail))
	}

	return rerr
}

func boolGauge(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func packageDir(info *debug.BuildInfo) string {
	pkgdir := strings.TrimPrefix(info.Path, info.Main.Path)
	if pkgdir == "" {
		pkgdir = "/"
	}
	return pkgdir
}

func scheduleUpdate(which Which, info *debug.BuildInfo, pol VersionPolicy, poltc GoVersionPolicy, tc Toolchains) (versionAvail, updateAvail bool, rerr error) {
	modpath := info.Main.Path

	log := slog.With("modpath", modpath)

	// If we don't know our current version, there's no point in looking for the latest version.
	if info.Main.Version == "" || info.Main.Version == "(devel)" {
		log.Debug("unknown current version, skipping check")
		return false, false, nil
	}

	// Look up latest version in DNS and/or Go module proxy.
	versions, err := lookupModuleVersions(log, modpath)
	if err != nil {
		return false, false, fmt.Errorf("looking up latest module versions for %q: %w", modpath, err)
	}

	// Log available versions.
	fulls := make([]string, len(versions))
	for i, v := range versions {
		fulls[i] = v.Full
	}
	log.Debug("latest available versions", "versions", fulls)

	// See if there's any update at all compared to current version, for metric.
	for _, nv := range versions {
		if semver.Compare(nv.Full, info.Main.Version) > 0 {
			versionAvail = true
			break
		}
	}

	// Determine if update is available according to policies, compared to what we
	// are currently running.
	iv, err := parseVersion(info.Main.Version, time.Time{})
	if err != nil {
		log.Error("parsing currently active version, ignoring", "err", err, "which", which, "version", info.Main.Version)
	} else {
		_, _, updateAvail, _ = policyPickVersion(log, pol, poltc, tc, iv, info.GoVersion, info.GoVersion, versions)
	}

	// Schedule updates, comparing against current modversion or updates already scheduled.
	modversion, goversion := latest(which, info)

	v, err := parseVersion(modversion, time.Time{})
	if err != nil {
		return false, false, fmt.Errorf("parsing current version: %v", err)
	}

	log = log.With("refversion", modversion, "refgoversion", goversion)

	nvers, ngovers, update, foundMajor := policyPickVersion(log, pol, poltc, tc, v, goversion, info.GoVersion, versions)
	if !foundMajor {
		log.Debug("no matching major version found")
		return
	} else if !update {
		log.Debug("no update found")
		return
	}
	log.Info("found new version", "newversion", nvers.Full, "newtoolchain", ngovers)
	if pol == VersionManual {
		log.Debug("not scheduling update due to policy manual")
		return
	}
	var sched Schedule = fallbackList(config.Update.schedule, defaults.Update.schedule)
	next := sched.Next(time.Now().Add(config.Update.Delay))
	schedule.Lock()
	if !config.Update.All {
		// Remove any pending updates for which.
		var l []Update
		for _, e := range schedule.updates {
			if e.Which != which {
				l = append(l, e)
			}
		}
		schedule.updates = l
	}
	schedule.updates = append(schedule.updates, Update{next, which, modpath, packageDir(info), nvers.Full, ngovers})
	reschedule()
	schedule.Unlock()
	return
}

// pick one of versions to update to (if any) based on reference vers and
// govers (with fallback to curgovers if govers can't be parsed), based on
// policies (pol, poltc).
func policyPickVersion(log *slog.Logger, pol VersionPolicy, poltc GoVersionPolicy, tc Toolchains, vers Version, govers, curgovers string, versions []Version) (nvers Version, ngovers string, update bool, foundMajor bool) {
	ngovers = govers
	// todo: could handle updating to a new release candidate.
	switch poltc {
	case GoVersionMinor:
		ngovers = tc.Cur
	case GoVersionPatch, GoVersionSupported, GoVersionFollow:
		t := strings.Split(ngovers, ".")
		if len(t) != 3 {
			log.Error("unrecognized goversion, sticking to current", "goversion", ngovers)
			ngovers = curgovers
		} else {
			prefix := strings.Join(t[:2], ".") + "."
			if strings.HasPrefix(tc.Cur, prefix) {
				ngovers = tc.Cur
			} else if strings.HasPrefix(tc.Prev, prefix) || poltc == GoVersionSupported || poltc == GoVersionFollow {
				ngovers = tc.Prev
			}
		}
		// ngovers can be updated below, for policy "follow" in case of a new service version.
	}

	// Schedule update according to policy.
	for _, nv := range versions {
		if nv.Major != vers.Major {
			continue
		}

		foundMajor = true

		// Once we find a version that is same or older, we can stop looking.
		if pol == VersionManual || nv.Minor < vers.Minor || nv.Minor == vers.Minor && (nv.Patch < vers.Patch || semver.Compare(nv.Full, vers.Full) <= 0) {
			break
		}

		if nv.Minor != vers.Minor && pol != VersionMinor {
			continue
		}

		// For a new release, update to latest toolchain, assuming application is tested with it.
		if poltc == GoVersionFollow {
			ngovers = tc.Cur
		}
		return nv, ngovers, true, foundMajor
	}

	return vers, ngovers, govers != ngovers, foundMajor
}

var errUpdateBusy = errors.New("update in progress")

// update puts a new binary in place and either updates this process (self) by
// exec-ing itself, or updates the managed service by sending the managed
// process a sigterm.
//
// When updating itself, when respWriter is not nil, its FD is passed to the
// newly exec-ed process, which will write an http response indicating a
// successful update.
func update(which Which, modpath, version, goversion string, up *Update, respWriter http.ResponseWriter, redirect bool, manual bool) (rerr error) {
	updating.Lock()
	if updating.busy {
		updating.Unlock()
		return errUpdateBusy
	}

	defer func() {
		if rerr != nil {
			// Don't register updating error for manually triggered updates. The operator will
			// know about this, no need to trigger alerts.
			if !manual {
				metricUpdateError.Inc()
			}
		}
		// For updates of the service, busy is cleared after a grace period. For
		// self-updates or errors, we clear it now.
		if which == Self || rerr != nil {
			updating.Lock()
			updating.busy = false
			updating.Unlock()
		}
	}()

	updating.busy = true
	updating.rolledback = false
	var info *debug.BuildInfo
	if which == Svc {
		info = updating.svcinfo
	} else {
		info = updating.selfinfo
	}
	updating.Unlock()

	dr, err := updateDownload(which, info, version, goversion)
	if err != nil {
		slog.Error("downloading update",
			"which", which,
			"modpath", modpath,
			"version", version,
			"goversion", goversion,
			"err", err)
		metricDownloadError.Inc()
		if up != nil {
			schedule.Lock()
			schedule.backoff++
			reschedule()
			schedule.Unlock()
		}
		return err
	}

	if up != nil {
		schedule.Lock()
		schedule.backoff = 0
		var l []Update
		for _, e := range schedule.updates {
			if e.Which != up.Which || e.Time.After(up.Time) {
				l = append(l, e)
			}
		}
		schedule.updates = l
		if err := writeScheduledTxt(schedule.updates); err != nil {
			slog.Error("update scheduled.txt", "err", err)
		}
		schedule.Unlock()
	}

	if err := updateInstall(which, dr, up == nil, respWriter, redirect); err != nil {
		// Clean up temporary file.
		if err := os.Remove(dr.tmpName); err != nil {
			slog.Error("cleaning up temporary file", "err", err, "tmpname", dr.tmpName)
		}
		return err
	}
	return nil
}

type downloadResult struct {
	// Path that we want to make the binary available as, as a symlink if currently
	// one, or a regular file otherwise.
	destPath string

	// Path of previous binary. If destPath is a symlink, this is the path it points
	// to. Otherwise it's equal to destPath.
	origBinPathAbs string

	// Temporary filename for the new binary, as returned by updateDownload.
	tmpName string

	// The intended filename instead of tmpName, including application and Go versions.
	// Caller should rename tmpName to versionPath and either make destPath a symlink
	// to this file (if currently a symlink), or rename it to destPath.
	versionPath string

	// Of previous/original binary, and new binary.
	originfo, newinfo *debug.BuildInfo
}

// updateDownload fetches a binary for an update to be installed.
// The new binary is placed in the same directory as the current binary (after
// following a potential symlink).
func updateDownload(which Which, originfo *debug.BuildInfo, version, goversion string) (downloadResult, error) {
	bs := buildSpec{
		Mod:       originfo.Main.Path,
		Version:   version,
		Dir:       packageDir(originfo),
		Goos:      runtime.GOOS,
		Goarch:    runtime.GOARCH,
		Goversion: goversion,
		Stripped:  true,
	}

	slog.Debug("lookup up binary", "buildspec", bs)
	t0 := time.Now()

	tlog.Lock()
	_, data, err := tlog.client.Lookup(bs.String())
	tlog.Unlock()
	slog.Debug("looking up binary at gobuild", "duration", time.Since(t0), "err", err)
	if err != nil {
		return downloadResult{}, fmt.Errorf("looking up binary: %w", err)
	}
	xbr, err := parseRecord(data)
	if err != nil {
		return downloadResult{}, fmt.Errorf("parsing record from tlog: %w", err)
	}
	br := *xbr
	if bs != br.buildSpec {
		return downloadResult{}, fmt.Errorf("tlog returned different buildspec %v, requested %v", br.buildSpec, bs)
	}
	url := downloadURL(br)
	slog.Debug("build result", "size", br.Filesize, "sum", br.Sum, "buildspec", bs)

	var destPath string
	if which == Self {
		destPath = os.Args[0]
	} else {
		destPath = cmdArgs[0]
	}

	dstDir := filepath.Dir(destPath)
	versionName := downloadFilename(br)
	versionPath := filepath.Join(dstDir, versionName)
	f, err := os.CreateTemp(dstDir, fmt.Sprintf("ysco.%s.*", versionName))
	if err != nil {
		return downloadResult{}, fmt.Errorf("create temp file for new binary: %w", err)
	}
	tmpName := f.Name()
	defer func() {
		if f != nil {
			if err := f.Close(); err != nil {
				slog.Error("closing temp file", "err", err)
			}
		}
		if tmpName != "" {
			if err := os.Remove(tmpName); err != nil {
				slog.Error("removing temp file", "err", err)
			}
		}
	}()
	slog.Debug("downloading", "url", url)
	td0 := time.Now()
	err = gobuildFetch(f, url, br.Sum)
	slog.Debug("downloading binary from gobuild", "duration", time.Since(td0), "err", err)
	if err != nil {
		return downloadResult{}, fmt.Errorf("fetching new binary: %v", err)
	}

	newinfo, err := buildinfo.ReadFile(tmpName)
	if err != nil {
		return downloadResult{}, fmt.Errorf("read file: %v", err)
	}

	if err := f.Close(); err != nil {
		return downloadResult{}, fmt.Errorf("close destination file: %v", err)
	}
	f = nil

	origBinPath, err := filepath.EvalSymlinks(destPath)
	if err != nil {
		return downloadResult{}, fmt.Errorf("eval symlinks for dest path: %v", err)
	}
	origBinPath, err = filepath.Abs(origBinPath)
	if err != nil {
		return downloadResult{}, fmt.Errorf("making original binary path absolute: %v", err)
	}

	// Copy permission modes (including setuid/setgid/sticky) and possibly uid/gid from previous binary.
	fi, err := os.Stat(destPath)
	if err != nil {
		return downloadResult{}, fmt.Errorf("stat binary for uid/gid and permissions: %v", err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return downloadResult{}, fmt.Errorf("fileinfo stat not a Stat_t but %T", fi.Sys())
	}
	if os.Getuid() == 0 {
		if err := os.Chown(tmpName, int(stat.Uid), int(stat.Gid)); err != nil {
			return downloadResult{}, fmt.Errorf("chown new binary: %v", err)
		}
	}
	if err := os.Chmod(tmpName, os.FileMode(stat.Mode&0o7777)); err != nil {
		return downloadResult{}, fmt.Errorf("chmod new binary: %v", err)
	}

	dr := downloadResult{destPath, origBinPath, tmpName, versionPath, originfo, newinfo}
	// Prevent cleanup.
	tmpName = ""

	return dr, err
}

// updateInstall installs an update. If which is Svc, the service is restarted.
// If which is Self, this function will not return on success because it has
// exec'ed itself.
//
// If manual is true, this update was initiated explicitly by the admin, eg through
// an HTTP request. Any scheduled updates for the same "which" are removed.
func updateInstall(which Which, dr downloadResult, manual bool, respWriter http.ResponseWriter, redirect bool) error {
	slog.Info("installing update",
		"which", which,
		"tmpname", dr.tmpName,
		"versionpath", dr.versionPath,
		"origbinpath", dr.origBinPathAbs,
		"path", dr.destPath,
		"origversion", dr.originfo.Main.Version,
		"origgoversion", dr.originfo.GoVersion,
		"newversion", dr.newinfo.Main.Version,
		"newgoversion", dr.newinfo.GoVersion,
		"manual", manual)

	if manual {
		scheduledCancel(which)
	} else {
		schedule.Lock()
		schedule.backoff = 0
		schedule.Unlock()
	}

	if _, err := os.Stat(dr.versionPath); err == nil {
		if isOldBinary(which, dr.versionPath) {
			if err := os.Remove(dr.versionPath); err != nil {
				return fmt.Errorf("target version path %s already existed, was previously installed, removing failed: %v", dr.versionPath, err)
			}
		} else {
			return fmt.Errorf("target version path %s already exists", dr.versionPath)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat target version path %s: %v", dr.versionPath, err)
	}

	if err := os.Rename(dr.tmpName, dr.versionPath); err != nil {
		return fmt.Errorf("rename temp file to version path %s: %v", dr.versionPath, err)
	}

	prevPathAbs, err := installBinary(dr.versionPath, dr.destPath, dr.originfo)
	if err != nil {
		return err
	}
	dr.versionPath = ""

	if which == Self {
		// Exec ourselves. We remove any pause.txt when we are back online again.

		oldBinaries.Lock()
		oldBinaries.Self = updateBinariesTxt(oldBinaries.Self, "old-binaries-self.txt", prevPathAbs, dr.origBinPathAbs)
		oldBinaries.Unlock()

		// We are either successful and don't return, or return an error.
		updating.Lock()
		defer updating.Unlock()
		err := execSelf(false, respWriter, redirect)
		return err
	}

	// todo: first terminate, then replace binary and start again?

	// Remove any pause.txt file that would prevent future automatic updates.
	os.Remove(filepath.Join(cacheDir, "pause.txt"))
	metricUpdatesPaused.Set(0)

	updating.Lock()
	updating.pauseReason = ""
	updating.svcinfoPrev = updating.svcinfo
	updating.binaryPathPrevAbs = prevPathAbs
	updating.svcinfo = dr.newinfo
	metricSvcVersion.Reset()
	metricSvcGoVersion.Reset()
	metricSvcVersion.WithLabelValues(updating.svcinfo.Main.Version).Set(1)
	metricSvcGoVersion.WithLabelValues(updating.svcinfo.GoVersion).Set(1)
	p := updating.process
	updating.Unlock()

	oldBinaries.Lock()
	oldBinaries.Svc = updateBinariesTxt(oldBinaries.Svc, "old-binaries-svc.txt", prevPathAbs, dr.origBinPathAbs)
	oldBinaries.Unlock()

	// todo: should we send signal to progress group instead of just process?
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending signal to command for restart to update: %v", err)
	}
	return nil
}

// must be called with updating lock held.
func execSelf(isConfigChange bool, respWriter http.ResponseWriter, redirect bool) error {
	p := updating.process
	started := updating.started
	selfinfo := updating.selfinfo
	es := execState{p.Pid, started, isConfigChange, selfinfo.Main.Version, selfinfo.GoVersion, 0, redirect}

	if respWriter != nil {
		var f *os.File
		if hj, ok := respWriter.(http.Hijacker); !ok {
			slog.Error("cannot get fd for connection, not a hijacker")
		} else if conn, _, err := hj.Hijack(); err != nil {
			slog.Error("hijacking connection", "err", err)
		} else if filer, ok := conn.(interface {
			File() (f *os.File, err error)
		}); !ok {
			slog.Error("cannot get file for connection")
		} else if f, err = filer.File(); err != nil {
			slog.Error("get file for connection", "err", err)
		} else if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, 0); err != nil {
			f.Close()
			slog.Error("clearing close-on-exec", "err", err)
		} else {
			es.RequestFD = f.Fd()
		}

		// Only called if we fail below. Otherwise we are replaced and this never executes.
		// This also keeps f alive.
		defer f.Close()
	}

	esbuf, err := json.Marshal(es)
	if err != nil {
		slog.Error("json marshal execstate", "err", err)
		return err
	}

	env := append(os.Environ(), fmt.Sprintf("_YSCO_EXEC=%s", esbuf))
	slog.Debug("exec with environment", "env", env)
	if err := unix.Exec(os.Args[0], os.Args, env); err != nil {
		slog.Error("exec", "err", err)
		return err
	}
	// We no longer exist!
	return nil
}

// must be called without oldBinaries locked.
func isOldBinary(which Which, path string) bool {
	oldBinaries.Lock()
	defer oldBinaries.Unlock()
	var l []string
	if which == Self {
		l = oldBinaries.Self
	} else {
		l = oldBinaries.Svc
	}
	return slices.Contains(l, path)
}

// must be called with oldBinaries locked.
// old is the current contents of the "old files" text file, at txtPath, which
// we'll rewrite. prevBinPathAbs is the path we want to add to that file, for
// future removal. newBinPathAbs is the new binary, we won't clean it up and won't
// add it to the txt file (that will happen with the next update).
func updateBinariesTxt(old []string, txtName, prevBinPathAbs, newBinPathAbs string) (newOld []string) {
	txtPath := filepath.Join(cacheDir, txtName)
	slog.Debug("maintenance for old binaries", "txtpath", txtPath, "prevbinpath", prevBinPathAbs, "newbinpath", newBinPathAbs)
	old = removeOldBinaries(old, newBinPathAbs)
	if prevBinPathAbs != newBinPathAbs {
		old = append(old, prevBinPathAbs)
	}
	data := []byte(strings.Join(old, "\n") + "\n")
	if err := os.WriteFile(txtPath, data, 0600); err != nil {
		slog.Warn("writing binaries text file for future cleanup", "err", err, "txtpath", txtPath)
	}
	return old
}

func listOldBinaries(txtPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, txtPath))
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

func removeOldBinary(p, newBinPathAbs string) (removed bool) {
	p, err := filepath.Abs(p)
	if err != nil {
		slog.Warn("evaluating old binary path to absolute path", "err", err, "oldpath", p)
		return false
	}
	if p == newBinPathAbs {
		slog.Warn("not removing old binary that is same as new binary", "path", p)
		return false
	}
	if isSymlinkDest(p, cmdArgs[0]) || isSymlinkDest(p, os.Args[0]) {
		slog.Warn("not removing old binary that is currently a symlink target", "oldpath", p)
		return false
	}

	if err := os.Remove(p); err != nil {
		slog.Error("removing old binary", "path", p, "err", err)
		return false
	}
	slog.Info("old binary removed", "path", p)
	return true
}

// removeOldBinaries removes paths from l, skipping those that are equal to
// newBinPathAbs, or where the current ysco or service binary is a symlink to a
// path.
func removeOldBinaries(l []string, newBinPathAbs string) (nl []string) {
	for _, p := range l {
		if ok := removeOldBinary(p, newBinPathAbs); !ok {
			nl = append(nl, p)
		}
	}
	return nl
}

func isSymlinkDest(pathAbs, link string) bool {
	s, err := os.Readlink(link)
	if err != nil {
		return false
	}
	s, err = filepath.Abs(s)
	if err != nil {
		return false
	}
	return s == pathAbs
}

// installBinary ensures the file at binPath is available at dstPath. Both files
// are in the same directory.
// If dstPath is currently a symlink, it is replaced with a symlink to binPath.
// Otherwise binPath is renamed to dstPath.
// The previous path is returned, it is always absolute.
func installBinary(binPath string, dstPath string, info *debug.BuildInfo) (prevPathAbs string, rerr error) {
	if fi, err := os.Lstat(dstPath); err != nil {
		return "", fmt.Errorf("lstat %s: %v", dstPath, err)
	} else if fi.Mode()&fs.ModeSymlink == 0 {
		slog.Info("installing binary, current path not a symlink", "path", dstPath)
		// Not a symlink. We'll move the current binary away and the new one in place.
		var suffix string
		if runtime.GOOS == "windows" {
			suffix += ".exe"
		}
		prevName := fmt.Sprintf("%s-%s-%s%s", path.Base(info.Main.Path), info.Main.Version, info.GoVersion, suffix)
		prevPathAbs = filepath.Join(filepath.Dir(binPath), prevName)
		prevPathAbs, err = filepath.Abs(prevPathAbs)
		if err != nil {
			return "", fmt.Errorf("absolute previous path %q: %v", prevPathAbs, err)
		}
		if _, err := os.Stat(prevPathAbs); err == nil {
			prevPathAbs += "." + genrandom()
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("stat %s, to move current binary to: %v", prevPathAbs, err)
		}
		if err := os.Rename(dstPath, prevPathAbs); err != nil {
			return "", fmt.Errorf("moving current binary %s out of the way to %s: %v", dstPath, prevPathAbs, err)
		}
		if err := os.Rename(binPath, dstPath); err != nil {
			return "", fmt.Errorf("moving new binary %s in place to %s: %v", binPath, dstPath, err)
		}
		slog.Info("current binary moved out of the way and new binary moved in place", "oldpath", prevPathAbs)
		return prevPathAbs, nil
	}

	// We'll remove the symlink and create a new one.
	slog.Info("installing binary, current path is a symlink", "path", dstPath)
	var err error
	prevPathAbs, err = os.Readlink(dstPath)
	if err != nil {
		return "", fmt.Errorf("reading destination of current symlink: %v", err)
	}
	if !filepath.IsAbs(prevPathAbs) {
		prevPathAbs, err = filepath.Abs(filepath.Join(filepath.Dir(dstPath), prevPathAbs))
		if err != nil {
			return "", fmt.Errorf("evaluting previous path to absolute: %v", err)
		}
	}
	if err := os.Remove(dstPath); err != nil {
		return "", fmt.Errorf("removing current binary symlink: %v", err)
	}
	if err := os.Symlink(filepath.Base(binPath), dstPath); err != nil {
		slog.Error("symlink new binary to current binary path", "err", err)
		if xerr := os.Symlink(prevPathAbs, dstPath); xerr != nil {
			slog.Error("restoring symlink after failure to create link failed", "err", xerr, "symlinkname", prevPathAbs, "symlinkdst", dstPath)
		}
		return "", fmt.Errorf("symlink new binary: %v", err)
	}
	slog.Info("new binary installed and symlinked", "symlinkname", binPath, "symlinkdst", dstPath, "prevpath", prevPathAbs)
	return prevPathAbs, nil
}

// called with "updating" lock held.
func updateRollback() error {
	slog.Warn("attempting to rollback to previous binary", "prevbinary", updating.binaryPathPrevAbs, "prevversion", updating.svcinfoPrev.Main.Version, "prevgoversion", updating.svcinfoPrev.GoVersion)

	if _, err := installBinary(updating.binaryPathPrevAbs, cmdArgs[0], updating.svcinfo); err != nil {
		return fmt.Errorf("restoring previous binary again: %v", err)
	}

	updating.svcinfo = updating.svcinfoPrev
	updating.svcinfoPrev = nil
	metricSvcVersion.Reset()
	metricSvcGoVersion.Reset()
	metricSvcVersion.WithLabelValues(updating.svcinfo.Main.Version).Set(1)
	metricSvcGoVersion.WithLabelValues(updating.svcinfo.GoVersion).Set(1)
	updating.binaryPathPrevAbs = ""
	return nil
}
