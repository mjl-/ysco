package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/sconf"
)

type VersionPolicy string

const (
	VersionPatch  VersionPolicy = "patch"
	VersionMinor  VersionPolicy = "minor"
	VersionManual VersionPolicy = "manual"
)

type GoVersionPolicy string

const (
	GoVersionPatch     GoVersionPolicy = "patch"
	GoVersionMinor     GoVersionPolicy = "minor"
	GoVersionManual    GoVersionPolicy = "manual"
	GoVersionSupported GoVersionPolicy = "supported"
	GoVersionFollow    GoVersionPolicy = "follow"
)

type Config struct {
	LogLevel string        `sconf-doc:"NOTE: Indenting in this config file can be done with tabs only, not spaces.\n\nValues 'debug', 'info', 'warn', 'error'. Default info."`
	AuthFile string        `sconf-doc:"Path to file with password to use for HTTP basic authentication (username is always 'admin')."`
	Monitor  ConfigMonitor `sconf:"optional" sconf-doc:"Settings for how to check for updates."`
	Policy   ConfigPolicy  `sconf:"optional" sconf-doc:"Policies for automated/manual updates."`
	Update   ConfigUpdate  `sconf:"optional" sconf-doc:"Settings for updating."`
	Gobuild  ConfigGobuild `sconf:"optional" sconf-doc:"Settings for the gobuilds.org service."`
	Links    []Link        `sconf:"optional" sconf-doc:"Links to show on admin page for convenience, e.g. to the service that is being run."`
	Process  ConfigProcess `sconf:"optional" sconf-doc:"Additional configuration for the service process."`

	adminPassword string // Read from AuthFile
}

type ConfigProcess struct {
	AmbientCapabilities []string `sconf:"optional" sconf-doc:"Capabilities to preserve in the service process, either by name or number, e.g. CAP_NET_BIND_SERVICE or 0xa. During fork and exec that sets a new user/group id, capabilities are dropped by default."`

	ambientCaps []uintptr // parsed form of AmbientCapabilities.
}

type MonitorMethod string

const (
	MonitorDNS     MonitorMethod = "dns"
	MonitorGoProxy MonitorMethod = "goproxy"
)

type ConfigMonitor struct {
	Methods          []MonitorMethod `sconf:"optional" sconf-doc:"Methods to use for finding updates. First successful method is used. Values 'dns', 'goproxy'. If empty, 'dns' and 'goproxy' are used."`
	DNS              string          `sconf:"optional" sconf-doc:"Gopherwatch DNS base hostname to use for looking up updates. If empty, l.gopherwatch.org is used."`
	GoProxy          string          `sconf:"optional" sconf-doc:"Base URL for Go module proxy. If empty, https://proxy.golang.org/cached-only/ is used."`
	GoProxyToolchain string          `sconf:"optional" sconf-doc:"If set, Go module proxy base URL to use for finding updates of Go toolchains."`
	Delay            time.Duration   `sconf:"optional" sconf-doc:"Wait time until first check for updates after starting up."`
	Interval         time.Duration   `sconf:"optional" sconf-doc:"Time between checks for updates."`
}

type ConfigPolicy struct {
	Service          VersionPolicy   `sconf:"optional" sconf-doc:"Policy for updating when a new version of the monitored service is discovered."`
	Self             VersionPolicy   `sconf:"optional" sconf-doc:"Policy for updating when a new version of ysco is discovered."`
	ServiceToolchain GoVersionPolicy `sconf:"optional" sconf-doc:"Policy for updating the monitored service when a new Go toolchain is discovered."`
	SelfToolchain    GoVersionPolicy `sconf:"optional" sconf-doc:"Policy for updating ysco when a new Go toolchain is discovered."`
}

type ConfigUpdate struct {
	Delay    time.Duration `sconf:"optional" sconf-doc:"Minimum wait time between discovery of update and rolling out the update."`
	Schedule []string      `sconf:"optional" sconf-doc:"When to do updates, e.g. during working hours, or only evenings or weekends. Specified as a list of periods, each entry with days and/or hours (no minute precision) separated by a space. Days and days are comma-separated, with the values a single day or an inclusive range. Hours always have to be specified as a range. Example: 'tu-th,sa' (any hour on these days), or '18-21' (any day between 18h and 21h), or 'mo-fr 9-17'. Updates are scheduled in the first available hour, taking backoff and jitter into account. If empty, all days/hours are allowed."`
	Jitter   time.Duration `sconf:"optional" sconf-doc:"Max random time to wait for performing the update within the scheduled hour."`
	All      bool          `sconf:"optional" sconf-doc:"Cycle through all discovered updates instead of cancelling a pending update when another new update is discovered."`

	schedule Schedule // Parsed form of Schedule.
}

type ConfigGobuild struct {
	VerifierKey string `sconf-doc:"For verifying the gobuild transparency log."`
	BaseURL     string `sconf:"optional" sconf-doc:"Base URL for gobuild service. Derived from VerifierKey by default."`
}

type Link struct {
	URL  string `sconf-doc:"Link shown on admin page, clickable."`
	Text string `sconf:"optional" sconf-doc:"Text to show next to link."`
}

var config Config
var defaults = Config{
	Monitor: ConfigMonitor{
		Methods:  []MonitorMethod{MonitorDNS, MonitorGoProxy},
		DNS:      "l.gopherwatch.org",
		GoProxy:  "https://proxy.golang.org/cached-only/",
		Delay:    time.Minute,
		Interval: 24 * time.Hour,
	},
	Policy: ConfigPolicy{
		Service:          VersionPatch,
		Self:             VersionPatch,
		ServiceToolchain: GoVersionFollow,
		SelfToolchain:    GoVersionFollow,
	},
	Update: ConfigUpdate{
		Delay:  3 * 24 * time.Hour,
		Jitter: time.Hour,
	},
	Gobuild: ConfigGobuild{
		VerifierKey: "beta.gobuilds.org+3979319f+AReBl47t6/Zl24/pmarcKhJtsfAU2c1F5Wtu4hrOgOQQ",
	},
}

func fallback[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
}

func fallbackList[T any](v, fallback []T) []T {
	if len(v) == 0 {
		return fallback
	}
	return v
}

func parseConfig(p string, c *Config) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseConfigReader(f, c)
}

func parseConfigReader(r io.Reader, c *Config) error {
	if err := sconf.Parse(r, c); err != nil {
		return err
	}

	if c.AuthFile == "" {
		return fmt.Errorf("AuthFile must be non-empty")
	}

	if data, err := os.ReadFile(c.AuthFile); err != nil {
		return fmt.Errorf("reading auth file %q: %v", c.AuthFile, err)
	} else {
		c.adminPassword = strings.TrimRight(string(data), "\n")
	}

	var level slog.LevelVar
	if err := level.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("parsing log level %q: %v", c.LogLevel, err)
	}

	for _, m := range c.Monitor.Methods {
		switch m {
		case MonitorDNS, MonitorGoProxy:
		default:
			return fmt.Errorf("invalid monitor method %q", m)
		}
	}

	if c.Monitor.GoProxy != "" {
		if _, err := url.Parse(c.Monitor.GoProxy); err != nil {
			return fmt.Errorf("invalid Go module proxy url %q: %v", c.Monitor.GoProxy, err)
		}
	}
	if c.Monitor.GoProxyToolchain != "" {
		if _, err := url.Parse(c.Monitor.GoProxyToolchain); err != nil {
			return fmt.Errorf("invalid Go module proxy for toolchains url %q: %v", c.Monitor.GoProxyToolchain, err)
		}
	}

	checkPolicy := func(p string, what string, tc bool) error {
		if p == "" {
			return nil
		}
		switch p {
		case "patch", "minor", "manual":
			return nil
		default:
			if tc {
				switch p {
				case "supported", "follow":
					return nil
				}
			}
		}
		return fmt.Errorf("invalid policy %q for new %s", p, what)
	}

	if err := checkPolicy(string(c.Policy.Service), "service versions", false); err != nil {
		return err
	}
	if err := checkPolicy(string(c.Policy.Self), "ysco versions", false); err != nil {
		return err
	}
	if err := checkPolicy(string(c.Policy.ServiceToolchain), "service toolchain versions", true); err != nil {
		return err
	}
	if err := checkPolicy(string(c.Policy.SelfToolchain), "ysco toolchain versions", true); err != nil {
		return err
	}

	if c.Update.Delay != 0 && c.Update.Delay <= 5*time.Second {
		return fmt.Errorf("update delay must be >= 5s due to potential for rollback of previous update")
	}
	for _, s := range c.Update.Schedule {
		dh, err := parseDayHour(s)
		if err != nil {
			return fmt.Errorf("parsing schedule line %q: %v", s, err)
		}
		c.Update.schedule = append(c.Update.schedule, dh)
	}

	if c.Gobuild.BaseURL != "" {
		if _, err := url.Parse(c.Gobuild.BaseURL); err != nil {
			return fmt.Errorf("invalid gobuild base url %q: %v", c.Gobuild.BaseURL, err)
		}
	}

	if len(c.Process.AmbientCapabilities) > 0 && runtime.GOOS != "linux" {
		return fmt.Errorf("capabilities only available on linux")
	}
	for _, s := range c.Process.AmbientCapabilities {
		cp, ok := capabilities[s]
		if !ok {
			v, err := strconv.ParseUint(s, 0, 64)
			if err != nil {
				return fmt.Errorf("unknown capability %q, and not a number", s)
			}
			cp = uintptr(v)
		}
		c.Process.ambientCaps = append(c.Process.ambientCaps, cp)
	}

	return nil
}
