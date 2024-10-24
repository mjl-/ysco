package main

import (
	"log/slog"
	"sort"
	"strconv"
	"strings"
)

func toolchains(goversions []string) Toolchains {
	// todo: replace with something less horrible and more efficient.

	type version struct {
		minor int
		patch int
		rc    int
		orig  string
	}
	versions := map[version]struct{}{}

	for _, v := range goversions {
		origv := v

		// "v0.0.1-go1.X(.Y|rcZ|betaZ)-$goos.$goarch"
		if !strings.HasPrefix(v, "v0.0.1-") {
			slog.Warn("unrecognized toolchain version, ignoring", "version", origv)
			continue
		}
		v = strings.TrimPrefix(v, "v0.0.1-")

		i := strings.LastIndex(v, ".") // For ".$goos-$goarch"
		if i < 0 {
			slog.Warn("no .$goos-$goarch suffix in go toolchain, ignoring", "version", origv)
			continue
		}
		v = v[:i]
		goversion := v

		if v == "go1.9.2rc2" {
			continue
		}
		if !strings.HasPrefix(v, "go1.") {
			slog.Warn("version does not start with 'go1.', ignoring", "version", origv)
			continue
		}
		v = v[len("go1."):]

		// Read minor.
		n := 0
		for _, c := range v {
			if c >= '0' && c <= '9' {
				n++
			} else {
				break
			}
		}
		if n == 0 {
			slog.Warn("no minor", "version", origv)
			continue
		}
		minor, err := strconv.ParseInt(v[:n], 10, 32)
		if err != nil {
			slog.Warn("parsing go version number, bad minor", "version", origv, "err", err)
			continue
		}
		v = v[n:]
		var patch, rc int64
		if v == "" {
			patch = 0
		} else if strings.HasPrefix(v, "rc") || strings.HasPrefix(v, "beta") {
			if strings.HasPrefix(v, "rc") {
				v = v[2:]
			} else {
				v = v[4:]
			}
			rc, err = strconv.ParseInt(v, 10, 32)
			if err != nil {
				slog.Error("parsing go version number, bad release candidate", "version", origv, "err", err)
				continue
			}
		} else if !strings.HasPrefix(v, ".") {
			slog.Error("parsing go version number, no dot after minor", "version", origv)
			continue
		} else if patch, err = strconv.ParseInt(v[1:], 10, 32); err != nil {
			slog.Error("parsing go version number, bad patch", "version", origv, "err", err)
			continue
		}

		versions[version{int(minor), int(patch), int(rc), goversion}] = struct{}{}
	}

	var l []version
	for v := range versions {
		l = append(l, v)
	}

	// Sort newest first.
	sort.Slice(l, func(i, j int) bool {
		a, b := l[i], l[j]
		if a.minor != b.minor {
			return a.minor > b.minor
		}
		if a.patch != b.patch {
			return a.patch > b.patch
		}
		if a.rc != b.rc && (a.rc == 0 || b.rc == 0) {
			return a.rc == 0
		}
		return a.rc > b.rc
	})

	var gonext, gocur, goprev *version
	var tc Toolchains

	// Look for next.
	if len(l) > 0 && l[0].rc != 0 {
		gonext = &l[0]
		tc.Next = gonext.orig
	}
	for len(l) > 0 && l[0].rc != 0 {
		l = l[1:]
	}

	if len(l) > 0 {
		gocur = &l[0]
		tc.Cur = gocur.orig
	}
	for len(l) > 0 && (l[0].minor == gocur.minor || l[0].rc != 0) {
		l = l[1:]
	}

	if len(l) > 0 {
		goprev = &l[0]
		tc.Prev = goprev.orig
	}

	return tc
}
