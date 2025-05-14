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
	- password.txt, contains password admin web interface.
	- state.json, lines with scheduled updates.
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
	mathrand "math/rand/v2"
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
var ysDir string    // For config, verifier cache and state file.
var username string // If set, we must be called as root and we'll start the process as this user. If group is not set explicitly, all groups of the user are set. If not a username, then interpreted as uid.
var groups string   // Only set this group (or comma-separated groups) when starting the process.

var logLevel slog.LevelVar

var cmdArgs []string // argv for starting service.

// Only meaningfull when username is set (was specified). Set once at startup.
var userID, groupID uint32
var groupIDs []uint32 // All groups, including primary group.

// State is stored in $ysDir/state.json. It also has private fields only used
// during runtime. Access is protected through the mutex. Private methods must only
// be called with the lock held.
type State struct {
	// private methods on State require holding the lock.
	sync.Mutex `json:"-"`

	// If non-empty, we are not currently doing automatic updates due to earlier
	// failure to update. Cleared after successful (e.g. manual) update.
	PauseReason string

	// All pending updates. When looking for next updates, we compare against the
	// latest (last) that we've already planned, not necessarily the current version.
	Schedule []Update

	// Previous binaries. We remove them when setting a new previous binary.
	PreviousBinarySvc  string
	PreviousBinarySelf string

	// Number of times we backed off. Each time we double number of hours delay (while
	// staying within update schedule. Cleared when we do a manual update and after
	// success.
	Backoff int

	// Reason we are doing backoff, e.g. error message.
	BackoffReason string

	// Fields above are exported and stored in state.json. Fields below are ephemeral.

	// If true, we are either waiting for the current old process to stop, or in the
	// first 5s after restarting the new service.
	updateBusy bool

	// Whether we rolled back the last update. If so, we won't try to rollback
	// again on command failure.
	rolledBack bool

	// Time of start of updated process. Used to recognize quick failure after updating
	// the service, causing us to rollback.
	processStarted time.Time

	// Active service process, to forward signals to, and send sigterm to when state.
	process *os.Process

	// Current service & self build info, read from files.
	svcinfo  debug.BuildInfo
	selfinfo debug.BuildInfo

	// Of previous binary, set when doing an update, for rollback.
	svcinfoPrev *debug.BuildInfo

	// Of new binary. Set when we before terminating the current process, and picked up
	// when it has terminated.
	svcNext *downloadResult

	// Fires when we can update.
	scheduleTimer *time.Timer
}

type Which string

const (
	Svc  Which = "svc"
	Self Which = "self"
)

type Update struct {
	Time      time.Time // Time at which update can be done.
	Which     Which     // "svc" or "self"
	ModPath   string    // E.g. "github.com/mjl-/moxtools"
	PkgDir    string    // E.g. "/" or "/cmd/somecommand".
	Version   string    // E.g. "v0.1.2"
	GoVersion string    // E.g. "go1.23.2"
}

func makeUpdate(which Which, info debug.BuildInfo) Update {
	return Update{
		time.Time{},
		which,
		info.Main.Path,
		packageDir(info),
		info.Main.Version,
		info.GoVersion,
	}
}

func (up Update) Equal(o Update) bool {
	return up.Time.UTC().Round(0).Equal(o.Time.UTC().Round(0)) && up.Which == o.Which && up.ModPath == o.ModPath && up.PkgDir == o.PkgDir && up.Version == o.Version && up.GoVersion == o.GoVersion
}

var state *State

// read state from $ysDir/state.json.
func readState() (*State, error) {
	p := filepath.Join(ysDir, "state.json")
	f, err := os.Open(p)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		var state State
		slog.Info("wrote initial state.json file")
		return &state, nil
	} else if err != nil {
		return nil, fmt.Errorf("open %q: %v", p, err)
	}
	var state State
	err = json.NewDecoder(f).Decode(&state)
	return &state, err
}

// write state to $ysDir/state.json.
func (st *State) write() (rerr error) {
	defer func() {
		if rerr != nil {
			slog.Error("writing state", "err", rerr)
		}
	}()

	p := filepath.Join(ysDir, "state.json")
	f, err := os.CreateTemp(ysDir, "state.json-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %v", err)
	}
	tmpName := f.Name()
	defer func() {
		if f != nil {
			if err := f.Close(); err != nil {
				log.Printf("close created temp file: %v", err)
			}
		}
		if tmpName != "" {
			if err := os.Remove(tmpName); err != nil {
				log.Printf("remove temp file: %v", err)
			}
		}
	}()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")
	if err := enc.Encode(st); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		f = nil
		return err
	}
	f = nil
	err = os.Rename(tmpName, p)
	if err == nil {
		tmpName = ""
	}
	return err
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

	var addr string
	var adminAddr string
	var metricsAddr string

	flg.StringVar(&ysDir, "dir", "ys", "directory with config file, state files and transparency log cache")
	flg.StringVar(&username, "user", "", "username/uid to run command as")
	flg.StringVar(&groups, "groups", "", "comma-separated groups/gids to run command as, overriding additional groups of system user")
	flg.StringVar(&addr, "addr", "", "address to webserve admin and metrics interfaces; cannot be used together with adminaddr and metricsaddr")
	flg.StringVar(&adminAddr, "adminaddr", "", "if non-empty, address to serve only admin webserver; also see -addr; see -adminauthfile for requiring authentication")
	flg.StringVar(&metricsAddr, "metricsaddr", "", "if non-empty, address to serve only metrics webserver; also see -addr")

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
		log.Fatalf("command path must be explicit path (absolute, or relative starting with ./ or ../)")
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

	state, err = readState()
	xcheckf(err, "read state")

	// Read module & version from binaries.
	svcinfo, err := buildinfo.ReadFile(cmdArgs[0])
	xcheckf(err, "reading buildinfo from command")
	selfinfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatalf("could not get buildinfo for own binary")
	}
	state.svcinfo = *svcinfo
	state.selfinfo = *selfinfo

	slog.Info("ysco starting", "version", selfinfo.Main.Version+"/"+selfinfo.GoVersion, "svc", svcinfo.Path, "svcversion", svcinfo.Main.Version+"/"+svcinfo.GoVersion, "adminaddr", adminAddr, "metricsaddr", metricsAddr, "goos", runtime.GOOS, "goarch", runtime.GOARCH)
	slog.Debug("service info", "modpath", svcinfo.Main.Path, "pkgdir", packageDir(state.svcinfo), "version", svcinfo.Main.Version, "goversion", svcinfo.GoVersion)
	slog.Debug("self info", "modpath", selfinfo.Main.Path, "pkgdir", packageDir(state.selfinfo), "version", selfinfo.Main.Version, "goversion", selfinfo.GoVersion)
	slog.Debug("starting service", "cmd", cmdArgs)

	metricSelfVersion.WithLabelValues(selfinfo.Main.Version).Set(1)
	metricSvcVersion.WithLabelValues(svcinfo.Main.Version).Set(1)
	metricSvcGoVersion.WithLabelValues(svcinfo.GoVersion).Set(1)
	metricSvcModPath.WithLabelValues(svcinfo.Main.Path).Set(1)

	if (svcinfo.Main.Version == "" || svcinfo.Main.Version == "(devel)") && fallback(config.Policy.Service, defaults.Policy.Service) != VersionManual {
		slog.Warn("version of module unknown, cannot compare versions for updates")
	}

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

	if state.PauseReason != "" {
		metricUpdatesPaused.Set(1)
		slog.Warn("automatic updates paused", "reason", state.PauseReason)
	}

	if len(state.Schedule) > 0 && state.scheduleRemoveUpdate(makeUpdate(Self, state.selfinfo)) {
		state.write()
	}
	state.scheduleTimer = time.NewTimer(0)
	state.scheduleTimer.Stop()
	state.reschedule()

	signalc := make(chan os.Signal, 1)
	signal.Notify(signalc, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	if statestr := os.Getenv("_YSCO_EXEC"); statestr != "" {
		pickupProcess(statestr)
	} else {
		state.startProcess()
	}

	// Wait for service process to finish, and send result to main loop (below).
	p := state.process
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
			state.Lock()
			err := state.process.Signal(sig)
			if err != nil {
				slog.Error("sending signal to process", "sig", sig, "err", err)
			}
			state.Unlock()

		// We are ready to install an update according to our scheduled updates.
		case <-state.scheduleTimer.C:
			updateUpcoming()

		// When the service command exits, we get its process state. If we are updating, we
		// restart the service, now with the new binary. If we weren't updating, we just
		// quit and let whoever supervises us restart us.
		case result := <-waitc:
			rstate, err := result.state, result.err
			if rstate != nil {
				usage := rstate.SysUsage()
				ru, ok := usage.(*syscall.Rusage)
				if !ok {
					slog.Error("rusage after command is not *syscall.Rusage but %T", usage)
				} else {
					state.Lock()
					start := state.processStarted
					state.Unlock()
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
			state.Lock()
			if state.svcNext != nil {
				// todo: recognize if the exit was actually due to the update?

				// Whether success or failure, we won't be trying this same update again.
				state.scheduleRemoveUpdate(makeUpdate(Svc, state.svcinfo))
				state.write()

				dr := state.svcNext
				state.svcNext = nil
				prevPathAbs, err := state.installBinary(dr.versionPath, dr.destPath, dr.originfo)
				if err != nil {
					slog.Error("installing new binary", "err", err)
					if err := os.Remove(dr.versionPath); err != nil {
						slog.Error("removing new binary after error", "err", err)
					}
					state.Backoff++
					state.BackoffReason = fmt.Sprintf("installing new binary: %v", err)
					state.write()
					continue
				}
				if state.PreviousBinarySvc != "" && state.PreviousBinarySvc != prevPathAbs && !isCurrentBinary(cmdArgs[0], state.PreviousBinarySvc) {
					slog.Info("removing previous service binary", "path", state.PreviousBinarySvc)
					if err := os.Remove(state.PreviousBinarySvc); err != nil {
						slog.Warn("removing previous binary", "err", err, "path", state.PreviousBinarySvc)
					}
				}
				state.PreviousBinarySvc = prevPathAbs
				state.write()

				state.svcinfoPrev = &state.svcinfo
				state.svcinfo = dr.newinfo

				metricSvcVersion.Reset()
				metricSvcGoVersion.Reset()
				metricSvcVersion.WithLabelValues(state.svcinfo.Main.Version).Set(1)
				metricSvcGoVersion.WithLabelValues(state.svcinfo.GoVersion).Set(1)

				state.startProcess()
				p := state.process
				state.Unlock()

				// After 5 seconds, mark as no longer updating and reschedule for possible next
				// update.
				go func() {
					time.Sleep(5 * time.Second)
					slog.Debug("clearing busy after 5s")
					state.Lock()
					state.updateBusy = false
					if state.Backoff > 0 {
						state.Backoff = 0
						state.BackoffReason = ""
						state.write()
					}
					state.reschedule()
					state.Unlock()
					slog.Debug("busy cleared")
				}()

				go func() {
					state, err := p.Wait()
					waitc <- waitResult{state, err}
				}()

				continue
			}
			if err != nil {
				// handleExit either quits or starts the service again, possibly after a rollback.
				state.handleExit("wait", err)
				state.Unlock()
			} else {
				slog.Info("service process finished without error, quitting")
				os.Exit(0)
			}
		}
	}
}

func isCurrentBinary(name, p string) bool {
	if fi, err := os.Lstat(name); err != nil {
		return false
	} else if fi.Mode()&os.ModeSymlink != 0 {
		name, err = os.Readlink(name)
		if err != nil {
			return false
		}
	}
	name, err := filepath.Abs(name)
	if err != nil {
		return false
	}
	return name == p
}

// remove an update from the schedule, its fields must match an scheduled update except for its Time field.
// caller should call st.write() to write the change to disk.
func (st *State) scheduleRemoveUpdate(up Update) (removed bool) {
	for i, e := range st.Schedule {
		up.Time = e.Time
		if e.Equal(up) {
			copy(st.Schedule[i:], st.Schedule[i+1:])
			st.Schedule = st.Schedule[:len(st.Schedule)-1]
			return true
		}
	}
	return false
}

// reschedule resets st.scheduleTimer based on scheduled updates.
func (st *State) reschedule() {
	// Update metrics with scheduled updates.
	var nself, nsvc float64
	for _, l := range st.Schedule {
		if l.Which == Self {
			nself++
		} else {
			nsvc++
		}
	}
	metricSelfUpdateScheduled.Set(nself)
	metricSvcUpdateScheduled.Set(nsvc)

	if st.PauseReason != "" || len(st.Schedule) == 0 {
		st.scheduleTimer.Stop()
		return
	}

	up := st.Schedule[0]
	tm := up.Time
	var backoff time.Duration
	for i := range st.Backoff {
		if i == 0 {
			backoff = time.Hour
		} else {
			backoff *= 2
		}
	}
	tm = tm.Add(backoff)
	// Find the next slot we can do the update.
	var sched Schedule = fallbackList(config.Update.schedule, defaults.Update.schedule)
	tm = sched.Next(tm)
	jitter := time.Duration(mathrand.Int64N(int64(fallback(config.Update.Jitter, defaults.Update.Jitter)/time.Second))) * time.Second
	tm = tm.Add(jitter)
	d := max(0, time.Until(tm))

	slog.Info("next update scheduled", "time", tm, "wait", d, "version", up.Version, "goversion", up.GoVersion, "modpath", up.ModPath, "pkgdir", up.PkgDir, "which", up.Which)
	st.scheduleTimer.Stop()
	st.scheduleTimer.Reset(d)
}

// updateUpcoming starts the first scheduled update if it still exists, its time has
// come, and no other update is busy.
func updateUpcoming() {
	state.Lock()
	if len(state.Schedule) == 0 || state.updateBusy {
		// If currently updating, once the update is done and stable, a next update will be scheduled.
		state.Unlock()
		return
	}
	// Otherwise, unlocked by updateLocked in goroutine.

	up := state.Schedule[0]
	if time.Until(up.Time) > 0 {
		state.reschedule()
		state.Unlock()
		return
	}

	go func() {
		// note: if up.Which is Self, update execs itself and never returns.
		err := updateLocked(up.Which, up.ModPath, up.Version, up.GoVersion, &up, nil, false)
		if err != nil {
			slog.Error("update failed", "err", err)
		}
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

	state.process, err = os.FindProcess(es.Pid)
	xcheckf(err, "finding process by pid")
	state.processStarted = es.Start

	slog.Info("ysco back after exec", "prev", es.OldVersion, "prevgo", es.OldGoVersion, "new", state.selfinfo.Main.Version, "newgo", state.selfinfo.GoVersion, "isconfigchange", es.IsConfigChange)

	if es.RequestFD <= 0 {
		return
	}

	f := os.NewFile(es.RequestFD, "requestfd")
	if f == nil {
		slog.Error("cannot make file from request fd")
		return
	}

	// todo: should we know about http/1 vs http/2?
	body := fmt.Sprintf("updated self from %s %s to %s %s\n", es.OldVersion, es.OldGoVersion, state.selfinfo.Main.Version, state.selfinfo.GoVersion)
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
	if err := resp.Write(f); err != nil {
		slog.Error("write response after exec", "err", err)
	}
	if err := f.Close(); err != nil {
		slog.Error("closing request fd", "err", err)
	}
}

func (st *State) startProcess() {
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
		st.handleExit("start", err)
		return
	}
	st.processStarted = t0
	st.process = cmd.Process
	if username != "" {
		slog.Debug("command started", "uid", userID, "gids", groupIDs)
	} else {
		slog.Debug("command started")
	}
}

func (st *State) handleExit(when string, err error) {
	slog.Error("command exited with error", "err", err, "when", when)
	code := 1
	if xerr, ok := err.(*exec.ExitError); ok {
		code = xerr.ExitCode()
	}

	if time.Since(st.processStarted) >= 5*time.Second {
		slog.Error("service quit, so will we", "exitcode", code)
		os.Exit(code)
	}
	if st.rolledBack {
		slog.Error("command quit within 5s after rollback, giving up", "err", err, "exitcode", code)
		os.Exit(code)
	}

	// We're going to rollback.
	st.rolledBack = true

	binName := fmt.Sprintf("%s-%s-%s", path.Base(st.svcinfo.Main.Path), st.svcinfo.Main.Version, st.svcinfo.GoVersion)
	st.PauseReason = fmt.Sprintf("binary %s exited within 5s: %v", binName, err)
	st.write()

	slog.Error("command exited within 5s after update, will attempt to roll back, and pausing further automatic updates", "err", err)
	metricSvcUpdateRollback.Inc()
	metricUpdatesPaused.Set(1)
	if err := st.rollbackBinary(); err != nil {
		slog.Error("rollback after failed update failed, giving up", "err", err)
		os.Exit(code)
	}
	slog.Warn("rolled back after failed update, restarting", "err", err)

	st.startProcess()
	p := st.process

	go func() {
		state, err := p.Wait()
		waitc <- waitResult{state, err}
	}()
}

func (st *State) scheduleRemoveWhich(which Which) (changed bool) {
	var l []Update
	for _, u := range st.Schedule {
		if u.Which != which {
			l = append(l, u)
		}
	}
	if len(st.Schedule) == len(l) {
		return false
	}
	st.Schedule = l
	return true
}

func (st *State) latest(which Which, info debug.BuildInfo) (version, goversion string) {
	for i := len(st.Schedule) - 1; i >= 0; i-- {
		if st.Schedule[i].Which == which {
			return st.Schedule[i].Version, st.Schedule[i].GoVersion
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

	state.Lock()
	svcinfo := state.svcinfo
	selfinfo := state.selfinfo
	state.Unlock()

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

func packageDir(info debug.BuildInfo) string {
	pkgdir := strings.TrimPrefix(info.Path, info.Main.Path)
	if pkgdir == "" {
		pkgdir = "/"
	}
	return pkgdir
}

// scheduleUpdate looks up the latest currently available modules for which, and
// adds a new update to the schedule according to the policy and any already
// scheduled updates.
func scheduleUpdate(which Which, info debug.BuildInfo, pol VersionPolicy, poltc GoVersionPolicy, tc Toolchains) (versionAvail, updateAvail bool, rerr error) {
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

	// Schedule updates, comparing against current lversion or updates already scheduled.
	state.Lock()
	lversion, lgoversion := state.latest(which, info)
	state.Unlock()

	lv, err := parseVersion(lversion, time.Time{})
	if err != nil {
		return false, false, fmt.Errorf("parsing current version: %v", err)
	}

	log = log.With("refversion", lversion, "refgoversion", lgoversion)

	nvers, ngovers, update, foundMajor := policyPickVersion(log, pol, poltc, tc, lv, lgoversion, info.GoVersion, versions)
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
	state.Lock()
	if !config.Update.All {
		state.scheduleRemoveWhich(which)
	}
	state.Schedule = append(state.Schedule, Update{next, which, modpath, packageDir(info), nvers.Full, ngovers})
	slices.SortFunc(state.Schedule, func(a, b Update) int { return a.Time.Compare(b.Time) })
	state.write()
	state.reschedule()
	state.Unlock()
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
func update(which Which, modpath, version, goversion string, up *Update, respWriter http.ResponseWriter, redirect bool) (rerr error) {
	state.Lock()
	if state.updateBusy {
		state.Unlock()
		return errUpdateBusy
	}
	return updateLocked(which, modpath, version, goversion, up, respWriter, redirect)
}

// must be called with lock held. will unlock before returning.
func updateLocked(which Which, modpath, version, goversion string, up *Update, respWriter http.ResponseWriter, redirect bool) (rerr error) {
	state.updateBusy = true
	state.rolledBack = false
	var info debug.BuildInfo
	if which == Svc {
		info = state.svcinfo
	} else {
		info = state.selfinfo
	}
	if up == nil && state.Backoff > 0 {
		state.Backoff = 0
		state.BackoffReason = ""
		state.write()
	}
	state.Unlock()

	dr, err := updateDownload(which, info, version, goversion)

	state.Lock()
	defer state.Unlock()
	defer func() {
		if rerr != nil {
			// Only register error in metric for scheduled updates. Operator knows about failures through web interface.
			if up == nil {
				metricUpdateError.Inc()
			}
		}

		// For updates of the service, busy is cleared after a grace period.
		if !(which == Svc && rerr == nil) {
			state.updateBusy = false
		}

		if rerr != nil && up != nil && len(state.Schedule) > 0 && state.Schedule[0].Equal(*up) {
			state.Backoff++
			state.BackoffReason = fmt.Sprintf("%v", err)
			state.write()
		}
		state.reschedule()
	}()

	if err != nil {
		slog.Error("downloading update",
			"which", which,
			"modpath", modpath,
			"version", version,
			"goversion", goversion,
			"err", err)
		metricDownloadError.Inc()
		return err
	}

	if err := state.initiateUpdate(which, dr, respWriter, redirect); err != nil {
		// Clean up temporary file.
		if err := os.Remove(dr.tmpName); err != nil {
			slog.Error("cleaning up temporary file", "err", err, "tmpname", dr.tmpName)
		}
		return err
	}
	if up != nil && state.scheduleRemoveUpdate(*up) {
		state.write()
		state.reschedule()
	}
	return nil
}

type downloadResult struct {
	// Path that we want to make the binary available as, as a symlink if currently
	// one, or a regular file otherwise.
	destPath string

	// Temporary filename for the new binary, as returned by updateDownload.
	tmpName string

	// The intended filename instead of tmpName, including application and Go versions.
	// Caller should rename tmpName to versionPath and either make destPath a symlink
	// to this file (if currently a symlink), or rename it to destPath.
	versionPath string

	// Of previous/original binary, and new binary.
	originfo, newinfo debug.BuildInfo
}

// updateDownload fetches a binary for an update to be installed.
// The new binary is placed in the same directory as the current binary (after
// following a potential symlink).
//
// Not called with state lock held, since this can take a while.
func updateDownload(which Which, originfo debug.BuildInfo, version, goversion string) (downloadResult, error) {
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

	dr := downloadResult{destPath, tmpName, versionPath, originfo, *newinfo}
	// Prevent cleanup.
	tmpName = ""

	return dr, err
}

// initiateUpdate starts updating to a new binary. If which is Self, the binary is
// installed and this process execs itself.
// If which is Svc, the new binary is stored in the state and the current process
// terminated with a signal. Once the process has quit, the main loop (elsewhere)
// will install the new binary and start the new process.
func (st *State) initiateUpdate(which Which, dr downloadResult, respWriter http.ResponseWriter, redirect bool) error {
	slog.Info("installing update",
		"which", which,
		"tmpname", dr.tmpName,
		"versionpath", dr.versionPath,
		"path", dr.destPath,
		"origversion", dr.originfo.Main.Version,
		"origgoversion", dr.originfo.GoVersion,
		"newversion", dr.newinfo.Main.Version,
		"newgoversion", dr.newinfo.GoVersion)

	if err := os.Rename(dr.tmpName, dr.versionPath); err != nil {
		return fmt.Errorf("rename temp file to version path %s: %v", dr.versionPath, err)
	}

	if which == Self {
		// Exec ourselves.

		prevPathAbs, err := st.installBinary(dr.versionPath, dr.destPath, dr.originfo)
		if err != nil {
			return err
		}
		dr.versionPath = ""

		// We are either successful and don't return, or return an error.
		if st.PreviousBinarySelf != "" && st.PreviousBinarySelf != prevPathAbs && !isCurrentBinary(os.Args[0], st.PreviousBinarySelf) {
			slog.Info("removing previous self binary", "path", st.PreviousBinarySelf)
			if err := os.Remove(st.PreviousBinarySelf); err != nil {
				slog.Warn("removing previous binary", "err", err, "path", st.PreviousBinarySelf)
			}
		}
		st.PreviousBinarySelf = prevPathAbs
		st.write()
		err = st.execSelf(false, respWriter, redirect)
		return err
	}

	st.svcNext = &dr

	// todo: should we send signal to progress group instead of just process?
	if err := st.process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("sending signal to command for restart to update: %v", err)
	}
	return nil
}

func (st *State) execSelf(isConfigChange bool, respWriter http.ResponseWriter, redirect bool) error {
	p := st.process
	started := st.processStarted
	selfinfo := st.selfinfo
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

// installBinary ensures the file at binPath is available at dstPath. Both files
// are in the same directory.
// If dstPath is currently a symlink, it is replaced with a symlink to binPath.
// Otherwise binPath is renamed to dstPath.
// The previous path is returned, it is always absolute.
func (st *State) installBinary(binPath string, dstPath string, curInfo debug.BuildInfo) (prevPathAbs string, rerr error) {
	if fi, err := os.Lstat(dstPath); err != nil {
		return "", fmt.Errorf("lstat %s: %v", dstPath, err)
	} else if fi.Mode()&fs.ModeSymlink == 0 {
		slog.Info("installing binary, current path not a symlink", "path", dstPath)
		// Not a symlink. We'll move the current binary away and the new one in place.
		var suffix string
		if runtime.GOOS == "windows" {
			suffix += ".exe"
		}
		prevName := fmt.Sprintf("%s-%s-%s%s", filepath.Base(curInfo.Path), curInfo.Main.Version, curInfo.GoVersion, suffix)
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

func (st *State) rollbackBinary() error {
	slog.Warn("attempting to rollback to previous binary", "prevbinary", st.PreviousBinarySvc, "prevversion", st.svcinfoPrev.Main.Version, "prevgoversion", st.svcinfoPrev.GoVersion)

	if _, err := st.installBinary(st.PreviousBinarySvc, cmdArgs[0], st.svcinfo); err != nil {
		return fmt.Errorf("restoring previous binary again: %v", err)
	}

	st.svcinfo = *st.svcinfoPrev
	st.svcinfoPrev = nil
	metricSvcVersion.Reset()
	metricSvcGoVersion.Reset()
	metricSvcVersion.WithLabelValues(st.svcinfo.Main.Version).Set(1)
	metricSvcGoVersion.WithLabelValues(st.svcinfo.GoVersion).Set(1)
	st.PreviousBinarySvc = ""
	return nil
}
