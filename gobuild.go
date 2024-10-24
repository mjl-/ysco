package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type buildSpec struct {
	Mod       string // E.g. github.com/mjl-/gobuild. Never starts or ends with slash, and is never empty.
	Version   string
	Dir       string // Always starts with slash. Never ends with slash unless "/".
	Goos      string
	Goarch    string
	Goversion string
	Stripped  bool
}

// Used in transparency log lookups, and used to calculate directory where build results are stored.
// Can be parsed with parseBuildSpec.
func (bs buildSpec) String() string {
	var variant string
	if bs.Stripped {
		variant = "-stripped"
	}
	return fmt.Sprintf("%s@%s/%s%s-%s-%s%s/", bs.Mod, bs.Version, bs.appendDir(), bs.Goos, bs.Goarch, bs.Goversion, variant)
}

// Variant of Dir that is either empty or otherwise has no leading but does have a
// trailing slash. Makes it easier to make some clean path by simple concatenation.
// Returns eg "" or "cmd/x/".
func (bs buildSpec) appendDir() string {
	if bs.Dir == "/" {
		return ""
	}
	return bs.Dir[1:] + "/"
}

type buildResult struct {
	buildSpec
	Filesize int64
	Sum      string
}

func parseRecord(data []byte) (*buildResult, error) {
	msg := string(data)
	if !strings.HasSuffix(msg, "\n") {
		return nil, fmt.Errorf("does not end in newline")
	}
	msg = msg[:len(msg)-1]
	t := strings.Split(msg, " ")
	if len(t) != 8 && len(t) != 9 {
		return nil, fmt.Errorf("bad record, got %d records, expected 8 or 9", len(t))
	}
	size, err := strconv.ParseInt(t[6], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad filesize %s: %v", t[6], err)
	}
	var stripped bool
	if len(t) == 9 {
		switch t[8] {
		case "":
		case "stripped":
			stripped = true
		default:
			return nil, fmt.Errorf("bad variant %s", t[8])
		}
	}
	br := &buildResult{buildSpec{t[0], t[1], t[2], t[3], t[4], t[5], stripped}, size, t[7]}
	return br, nil
}

func downloadURL(r buildResult) string {
	var variant string
	if r.Stripped {
		variant = "-stripped"
	}
	return fmt.Sprintf("%s/%s@%s/%s%s-%s-%s%s/%s/%s.gz", tlog.ops.dlBaseURL, r.Mod, r.Version, r.appendDir(), r.Goos, r.Goarch, r.Goversion, variant, r.Sum, downloadFilename(r))
}

// Name of file the browser will save the file as.
func downloadFilename(r buildResult) string {
	var name string
	if r.Dir != "/" {
		name = path.Base(r.Dir)
	} else {
		name = path.Base(r.Mod)
	}
	ext := ""
	if r.Goos == "windows" {
		ext = ".exe"
	}
	var variant string
	if r.Stripped {
		variant = "-stripped"
	}
	return fmt.Sprintf("%s-%s-%s%s%s", name, r.Version, r.Goversion, variant, ext)
}

func gobuildFetch(f *os.File, url, sum string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("new http request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request to download binary: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("remote http response for downloading binary: %s", resp.Status)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gunzip binary: %v", err)
	}

	h := sha256.New()
	df := io.MultiWriter(h, f)
	if _, err := io.Copy(df, gzr); err != nil {
		return fmt.Errorf("downloading binary: %v", err)
	}
	if err := gzr.Close(); err != nil {
		return fmt.Errorf("close gzip stream: %v", err)
	}

	sha := h.Sum(nil)
	dlSum := "0" + base64.RawURLEncoding.EncodeToString(sha[:20])
	if dlSum != sum {
		return fmt.Errorf("downloaded binary has sum %s, expected %s", dlSum, sum)
	}
	slog.Debug("sum of downloaded file matches")

	// Attempt to make file executable.
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat temp file: %v", err)
	}
	// Set the "x" bit for the positions that have the "r" bit.
	mode := info.Mode() | (0111 & (info.Mode() >> 2))
	if err := f.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("making binary executable: %v", err)
	}

	return nil
}
