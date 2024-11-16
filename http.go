package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"

	"golang.org/x/mod/semver"
)

//go:embed "favicon.ico"
var faviconIco embed.FS

//go:embed "index.html"
var indexHTML string

var indextempl = htmltemplate.Must(htmltemplate.New("index.html").Funcs(htmltemplate.FuncMap{
	"tagURL": tagURL,
}).Parse(indexHTML))

// tagURL returns a guessed url to the tag in source control that may contain
// release notes, but may also be an incorrect url.
func tagURL(modpath, version string) string {
	var repoURL, tagURL string

	// Based on code from github.com/mjl-/gopherwatch, compose.go.
	t := strings.Split(modpath, "/")
	host := t[0]
	if strings.Contains(host, "github") && len(t) >= 3 {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/releases/tag/" + url.QueryEscape(strings.Join(append(t[3:], version), "/"))
	} else if strings.Contains(host, "gitlab") && len(t) >= 3 {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/-/tags/" + version
	} else if strings.Contains(host, "codeberg") {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/releases/tag/" + version
	} else if strings.Contains(host, "sr.ht") {
		repoURL = "https://" + strings.Join(t[:3], "/")
		tagURL = repoURL + "/refs/" + version
	} else if host == "golang.org" && len(t) >= 3 && t[1] == "x" {
		repoURL = "https://github.com/golang/" + t[2]
		tagURL = repoURL + "/releases/tag/" + url.QueryEscape(strings.Join(append(t[3:], version), "/"))
	}
	// bitbucket doesn't seem to have a URL for just the tag (and the message associated), only trees or commits.

	return tagURL
}

func httpErrorf(w http.ResponseWriter, r *http.Request, code int, format string, args ...any) {
	err := fmt.Sprintf(format, args...)
	if code/100 == 5 {
		slog.Error("http server error", "code", code, "err", err, "method", r.Method, "path", r.URL.Path)
	} else {
		slog.Debug("http server error", "code", code, "err", err, "method", r.Method, "path", r.URL.Path)
	}
	http.Error(w, fmt.Sprintf("%d - %s - %s", code, http.StatusText(code), err), code)
}

type indexArgs struct {
	SvcModPath        string
	SvcPkgDir         string
	SvcVersion        string
	SvcGoVersion      string
	SelfModPath       string
	SelfPkgDir        string
	SelfVersion       string
	SelfGoVersion     string
	PauseReason       string
	Scheduled         []Update
	OldBinariesSelf   []string
	OldBinariesSvc    []string
	SvcVersionsError  string
	SvcVersions       []string
	SelfVersionsError string
	SelfVersions      []string
	GoVersionsError   string
	GoVersions        []string
	Argv              []string
}

func gatherIndexArgs() indexArgs {
	schedule.Lock()
	scheduled := append([]Update{}, schedule.updates...)
	schedule.Unlock()

	updating.Lock()
	pauseReason := updating.pauseReason
	svcinfo := updating.svcinfo
	selfinfo := updating.selfinfo
	updating.Unlock()

	oldBinaries.Lock()
	oldbinsself := append([]string{}, oldBinaries.Self...)
	oldbinssvc := append([]string{}, oldBinaries.Svc...)
	oldBinaries.Unlock()

	// todo: do lookups in goroutines.

	// Lookup all available versions.
	var svcversions []string
	var svcversionsError string
	l, err := lookupModuleVersions(slog.Default(), svcinfo.Main.Path)
	if err != nil {
		svcversionsError = err.Error()
	}
	for _, v := range l {
		svcversions = append(svcversions, v.Full)
	}
	if len(svcversions) == 0 && (svcinfo.Main.Version != "" && svcinfo.Main.Version != "(devel)") {
		svcversions = append(svcversions, svcinfo.Main.Version)
	}

	var selfversions []string
	var selfversionsError string
	l, err = lookupModuleVersions(slog.Default(), selfinfo.Main.Path)
	if err != nil {
		selfversionsError = err.Error()
	}
	for _, v := range l {
		selfversions = append(selfversions, v.Full)
	}
	if len(selfversions) == 0 && (selfinfo.Main.Version != "" && selfinfo.Main.Version != "(devel)") {
		selfversions = append(selfversions, selfinfo.Main.Version)
	}

	var goversions []string
	var goversionsError string
	tc, err := lookupToolchainVersions(slog.Default())
	if err != nil {
		goversionsError = err.Error()
	}
	if tc.Cur != "" {
		goversions = append(goversions, tc.Cur)
	}
	if tc.Prev != "" {
		goversions = append(goversions, tc.Prev)
	}
	if tc.Next != "" {
		goversions = append(goversions, tc.Next)
	}

	return indexArgs{
		svcinfo.Main.Path,
		packageDir(svcinfo),
		svcinfo.Main.Version,
		svcinfo.GoVersion,
		selfinfo.Main.Path,
		packageDir(selfinfo),
		selfinfo.Main.Version,
		selfinfo.GoVersion,
		pauseReason,
		scheduled,
		oldbinsself,
		oldbinssvc,
		svcversionsError,
		svcversions,
		selfversionsError,
		selfversions,
		goversionsError,
		goversions,
		os.Args,
	}
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, faviconIco, "favicon.ico")
}

func handleJSONGet(w http.ResponseWriter, r *http.Request) {
	authok := adminAuth == "" || r.Header.Get("Authorization") == adminAuth
	if !authok {
		w.Header().Set("WWW-Authenticate", "Basic")
		httpErrorf(w, r, http.StatusUnauthorized, "bad/missing credentials")
		return
	}

	buf, err := json.Marshal(gatherIndexArgs())
	if err != nil {
		httpErrorf(w, r, http.StatusInternalServerError, "marshal json: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(buf)
}

func handleIndexGet(w http.ResponseWriter, r *http.Request) {
	authok := adminAuth == "" || r.Header.Get("Authorization") == adminAuth
	if !authok {
		w.Header().Set("WWW-Authenticate", "Basic")
		httpErrorf(w, r, http.StatusUnauthorized, "bad/missing credentials")
		return
	}

	var b bytes.Buffer
	if err := indextempl.Execute(&b, gatherIndexArgs()); err != nil {
		slog.Error("execute template", "err", err)
		httpErrorf(w, r, http.StatusInternalServerError, "executing template: %v", err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b.Bytes())
}

func handleIndexPost(w http.ResponseWriter, r *http.Request) {
	authok := adminAuth == "" || r.Header.Get("Authorization") == adminAuth
	if !authok {
		w.Header().Set("WWW-Authenticate", "Basic")
		httpErrorf(w, r, http.StatusUnauthorized, "bad/missing credentials")
		return
	}

	cmd := r.FormValue("command")

	switch cmd {
	case "check":
		// Check for updates. In foreground, so loading the page afterwards has the latest
		// scheduled updates.
		err := monitorOne()
		if err != nil {
			httpErrorf(w, r, http.StatusInternalServerError, "updating: %v", err)
			return
		}

	case "update":
		which := Which(r.FormValue("which"))
		version := r.FormValue("version")
		goversion := r.FormValue("goversion")
		if version == "" || goversion == "" || (which != Svc && which != Self) {
			httpErrorf(w, r, http.StatusBadRequest, "missing/empty version or goversion or missing/invalid which")
			return
		}

		var info *debug.BuildInfo
		updating.Lock()
		if which == Self {
			info = updating.selfinfo
		} else {
			info = updating.svcinfo
		}
		updating.Unlock()

		var respWriter http.ResponseWriter
		if which == Self {
			respWriter = w
		}
		// note: if which is Self, and the update is successful, the process is replaced and this won't return.
		if err := update(which, info.Main.Path, packageDir(info), version, goversion, nil, respWriter, true, true); err != nil {
			if errors.Is(err, errUpdateBusy) {
				httpErrorf(w, r, http.StatusBadRequest, "update busy")
			} else {
				httpErrorf(w, r, http.StatusInternalServerError, "updating: %v", err)
			}
			return
		}

	default:
		httpErrorf(w, r, http.StatusBadRequest, "unknown command %q", cmd)
		return
	}

	http.Redirect(w, r, ".", http.StatusSeeOther)
}

func handleNotify(w http.ResponseWriter, r *http.Request) {
	// note: No authentication.
	slog.Debug("notification for module update")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
	if policySvc == "manual" && policySelf == "manual" {
		return
	}
	// In background, we want to return immediately since this is a webhook.
	monitort.Reset(0)
}

func handleNotifyToolchain(w http.ResponseWriter, r *http.Request) {
	// note: No authentication.
	slog.Debug("notification for toolchain update")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
	if policySvcToolchain == "manual" && policySelfToolchain == "manual" {
		return
	}
	// In background, we want to return immediately since this is a webhook.
	monitort.Reset(0)
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	which := Which(r.FormValue("which"))
	version := r.FormValue("version")
	goversion := r.FormValue("goversion")
	authok := adminAuth == "" || r.Header.Get("Authorization") == adminAuth
	slog.Debug("update request", "which", which, "version", version, "goversion", goversion, "authok", authok)

	if !authok {
		w.Header().Set("WWW-Authenticate", "Basic")
		httpErrorf(w, r, http.StatusUnauthorized, "bad/missing credentials")
		return
	}

	if version == "" || goversion == "" || (which != Self && which != Svc) {
		httpErrorf(w, r, http.StatusBadRequest, "missing version or goversion or missing/invalid 'which'")
		return
	}
	updating.Lock()
	var info *debug.BuildInfo
	if which == Self {
		info = updating.selfinfo
	} else {
		info = updating.svcinfo
	}
	updating.Unlock()
	lversion, lgoversion := latest(which, info)

	if version == "latest" {
		versions, err := lookupModuleVersions(slog.Default(), info.Main.Path)
		if err != nil {
			httpErrorf(w, r, http.StatusInternalServerError, "fetch latest version: %v", err)
			return
		}
		for _, v := range versions {
			if semver.Major(v.Full) == semver.Major(lversion) {
				version = v.Full
			}
		}
		if version == "latest" {
			httpErrorf(w, r, http.StatusInternalServerError, "no latest module for current major version found, may be too old")
			return
		}
	} else if version == "current" {
		version = info.Main.Version
	} else {
		// todo: check the version exists? probably not needed, an error will show up later.
	}

	if goversion == "latest" {
		tc, err := lookupToolchainVersions(slog.Default())
		if err == nil && tc.Cur == "" {
			err = fmt.Errorf("no current toolchain found")
		}
		if err != nil {
			httpErrorf(w, r, http.StatusInternalServerError, "looking up latest toolchains: %v", err)
			return
		}
		goversion = tc.Cur
	} else if version == "current" {
		version = info.GoVersion
	} else {
		// todo: check the version exists? probably not needed, an error will show up later.
	}

	if version == lversion && goversion == lgoversion {
		httpErrorf(w, r, http.StatusBadRequest, "already at requested version")
		return
	}

	var respWriter http.ResponseWriter
	if which == Self {
		respWriter = w
	}
	// note: if which is Self, and the update successful, the process is replaced and never returns.
	if err := update(which, info.Main.Path, packageDir(info), version, goversion, nil, respWriter, false, true); err != nil {
		if errors.Is(err, errUpdateBusy) {
			httpErrorf(w, r, http.StatusBadRequest, "update busy")
		} else {
			httpErrorf(w, r, http.StatusInternalServerError, "updating: %v", err)
		}
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}
