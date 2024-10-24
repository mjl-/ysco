package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func fetchGoProxy(ctx context.Context, goproxy, modpath string) ([]string, error) {
	if !strings.HasSuffix(goproxy, "/") {
		goproxy += "/"
	}
	escpath, err := module.EscapePath(modpath)
	if err != nil {
		return nil, fmt.Errorf("escape path: %v", err)
	}
	goproxy += escpath + "/@v/list"

	req, err := http.NewRequestWithContext(ctx, "GET", goproxy, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http transaction: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(&limitReader{1024 * 1024, resp.Body})
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("got status %s, expected 200 ok (%q)", resp.Status, data)
	} else if err != nil {
		err = fmt.Errorf("read http response data: %v", err)
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		// todo: possibly lookup @latest for a pseudorelease version? eg v0.0.0-20240909094216-5b446ab2b88c
		return nil, nil
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

type limitReader struct {
	N int
	R io.Reader
}

func (r *limitReader) Read(buf []byte) (int, error) {
	nn, err := r.R.Read(buf)
	if nn > 0 {
		r.N -= nn
	}
	if (err == nil || err == io.EOF) && r.N < 0 {
		return nn, fmt.Errorf("too large")
	}
	return nn, err
}

func lookupToolchainVersionGoProxy(ctx context.Context, goproxy string) (Toolchains, error) {
	t0 := time.Now()
	l, err := fetchGoProxy(ctx, goproxy, "golang.org/toolchain")
	slog.Debug("goproxy lookup for toolchain", "duration", time.Since(t0), "err", err)
	if err != nil {
		return Toolchains{}, err
	}
	return toolchains(l), nil
}

func lookupModuleVersionsGoProxy(ctx context.Context, goproxy, modpath string) ([]Version, error) {
	t0 := time.Now()
	l, err := fetchGoProxy(ctx, goproxy, modpath)
	slog.Debug("goproxy lookup for module", "duration", time.Since(t0), "err", err)
	if err != nil {
		return nil, err
	}

	var zerotime time.Time
	var versions []Version
	for _, vs := range l {
		v, err := parseVersion(vs, zerotime)
		if err != nil {
			return nil, fmt.Errorf("parsing version %q: %v", vs, err)
		}
		versions = append(versions, v)
	}

	sort.Slice(versions, func(i, j int) bool {
		return semver.Compare(versions[i].Full, versions[j].Full) > 0
	})

	return versions, nil
}
