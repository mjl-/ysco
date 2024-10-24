package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/module"
)

// Toolchains holds the latest toolchains. It is the parsed form of the DNS TXT
// toolchain record.
type Toolchains struct {
	Cur       string
	Prev      string
	Next      string
	CurFound  time.Time `json:",omitempty"`
	PrevFound time.Time `json:",omitempty"`
	NextFound time.Time `json:",omitempty"`
}

// Version is a parsed module version as returned by a gopherwatch v0 DNS TXT record.
type Version struct {
	Full                string
	Major, Minor, Patch int
	Pre                 string
	Found               time.Time `json:",omitempty"`
}

// ErrNotFound is returned by LookupToolchains and LookupModule when the module
// isn't found.
var ErrNotFound = errors.New("module not found")

// LookupToolchains looks up the latest toolchains over DNS at the given base
// domain, e.g. "l.gopherwatch.org".
func LookupToolchains(ctx context.Context, baseDomain string) (Toolchains, error) {
	t0 := time.Now()
	name := "toolchain.v0." + strings.TrimSuffix(baseDomain, ".") + "."
	l, err := net.DefaultResolver.LookupTXT(ctx, name)
	slog.Debug("dns lookup for toolchain", "duration", time.Since(t0), "err", err)
	if err != nil {
		return Toolchains{}, fmt.Errorf("lookup toolchains in dns: %w", err)
	}
	if len(l) == 0 {
		return Toolchains{}, ErrNotFound
	}
	s := strings.Join(l, "")
	return parseToolchains(s)
}

// LookupModule looks up the latest version(s) of a module over DNS at the
// given base domain, e.g. "l.gopherwatch.org".
func LookupModule(ctx context.Context, baseDomain, modpath string) ([]Version, error) {
	name, err := lookupName(baseDomain, modpath)
	if err != nil {
		return nil, err
	}

	t0 := time.Now()
	l, err := net.DefaultResolver.LookupTXT(ctx, name)
	slog.Debug("dns lookup for module", "duration", time.Since(t0), "err", err)
	if err != nil {
		return nil, fmt.Errorf("lookup module version in dns: %w", err)
	}
	if len(l) == 0 {
		return nil, ErrNotFound
	}
	return parseVersions(strings.Join(l, ""))
}

func lookupName(baseDomain, modpath string) (string, error) {
	// Check if a valid path. Special characters, unicode, is not allowed.
	if err := module.CheckPath(modpath); err != nil {
		return "", err
	}

	i := strings.Index(modpath, "/")
	if i < 0 {
		return "", fmt.Errorf("missing slash in modpath")
	}
	host := strings.ToLower(modpath[:i])
	modpath = modpath[i+1:]
	var elems []string
	modpathelems := strings.Split(modpath, "/")
	for i := len(modpathelems) - 1; i >= 0; i-- {
		s := modpathelems[i]
		if s == "" {
			return "", fmt.Errorf("bad module path, empty element or double slash")
		}
		var elem string
		for _, c := range []byte(s) {
			switch {
			case c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c == '-':
				elem += string(rune(c))
			default:
				elem += fmt.Sprintf("_%02x", c)
			}
		}

		if strings.HasPrefix(elem, "-") {
			elem = "_2d" + elem[1:]
		}
		if strings.HasSuffix(elem, "-") {
			elem = elem[:len(elem)-1] + "_2d"
		}
		if len(elem) > 63 {
			return "", fmt.Errorf("dns label %q larger than 63 bytes for module path elem %q", elem, s)
		}
		elems = append(elems, elem)
	}

	name := fmt.Sprintf("%s._.%s.v0.%s", strings.Join(elems, "."), host, strings.TrimSuffix(baseDomain, ".")+".")
	return name, nil
}

func parseVersions(txt string) ([]Version, error) {
	var r []Version
	for _, s := range strings.Split(txt, ";") {
		s = strings.TrimSpace(s)
		m := map[string]string{}
		for _, kv := range strings.Split(s, " ") {
			t := strings.SplitN(kv, "=", 2)
			if len(t) != 2 {
				return nil, fmt.Errorf("bad response kv %q in %q", kv, txt)
			}
			if t[1] == "" {
				return nil, fmt.Errorf("bad response, empty value in %v", txt)
			}
			if m[t[0]] != "" {
				return nil, fmt.Errorf("duplicate key %q in %v", t[0], txt)
			}
			m[t[0]] = t[1]
		}
		if m["v"] == "" || m["t"] == "" {
			continue
		}
		full := m["v"]
		t, err := strconv.ParseUint(m["t"], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("bad time %q in %v", m["t"], txt)
		}
		found := time.Unix(int64(t), 0)
		v, err := parseVersion(full, found)
		if err != nil {
			return nil, fmt.Errorf("parsing %v in %q: %v", full, txt, err)
		}
		r = append(r, v)
	}
	return r, nil
}

func parseVersion(full string, found time.Time) (Version, error) {
	pt := strings.SplitN(full, "-", 2)
	var pre string
	if len(pt) == 2 {
		pre = pt[1]
	}
	vt := strings.SplitN(pt[0], ".", 3)
	if len(vt) != 3 {
		return Version{}, fmt.Errorf("bad version, not 3 dots")
	}
	major, err := strconv.ParseUint(strings.TrimPrefix(vt[0], "v"), 10, 32)
	if err != nil {
		return Version{}, fmt.Errorf("bad major")
	}
	minor, err := strconv.ParseUint(vt[1], 10, 32)
	if err != nil {
		return Version{}, fmt.Errorf("bad minor")
	}
	patch, err := strconv.ParseUint(vt[2], 10, 32)
	if err != nil {
		return Version{}, fmt.Errorf("bad patch")
	}
	return Version{full, int(major), int(minor), int(patch), pre, found}, nil
}

func parseToolchains(txt string) (Toolchains, error) {
	var tc, ztc Toolchains
	for _, s := range strings.Split(txt, ";") {
		s = strings.TrimSpace(s)
		m := map[string]string{}
		for _, kv := range strings.Split(s, " ") {
			t := strings.SplitN(kv, "=", 2)
			if len(t) != 2 {
				return ztc, fmt.Errorf("bad response kv %q in %q", kv, txt)
			}
			if t[1] == "" {
				return ztc, fmt.Errorf("bad response, empty value in %v", txt)
			}
			if m[t[0]] != "" {
				return ztc, fmt.Errorf("duplicate key %q in %v", t[0], txt)
			}
			m[t[0]] = t[1]
		}
		if m["v"] == "" || m["t"] == "" || m["k"] == "" {
			continue
		}
		t, err := strconv.ParseUint(m["t"], 16, 64)
		if err != nil {
			return ztc, fmt.Errorf("bad time %q in %v", m["t"], txt)
		}
		found := time.Unix(int64(t), 0)
		v := m["v"]
		k := m["k"]
		switch {
		case k == "cur" && tc.Cur == "":
			tc.Cur = v
			tc.CurFound = found
		case k == "prev" && tc.Prev == "":
			tc.Prev = v
			tc.PrevFound = found
		case k == "next" && tc.Next == "":
			tc.Next = v
			tc.NextFound = found
		}
	}
	if tc == ztc {
		return ztc, fmt.Errorf("no version in response %q", txt)
	}
	return tc, nil
}
