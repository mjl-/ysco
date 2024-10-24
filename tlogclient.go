package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/mjl-/ysco/internal/sumdb"
)

type clientOps struct {
	localDir  string // e.g. yscocache/gobuildverifier/beta.gobuilds.org, for config and cache subdirs.
	baseURL   string // e.g. https://beta.gobuilds.org/tlog
	dlBaseURL string // e.g. https://beta.gobuilds.org
}

var _ sumdb.ClientOps = (*clientOps)(nil)

func newClient(vkey string, baseURL, baseDir string) (*sumdb.Client, *clientOps, error) {
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing verifier key: %v", err)
	}

	if baseURL == "" {
		name := verifier.Name()
		if strings.Contains(name, ".") {
			baseURL = "https://" + name + "/tlog"
		} else {
			baseURL = "http://" + name + ":8000/tlog"
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")

	ops := &clientOps{
		filepath.Join(baseDir, verifier.Name()),
		baseURL,
		strings.TrimSuffix(baseURL, "/tlog"),
	}

	if ovkey, err := ops.ReadConfig("key"); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("reading verifierkey: %v", err)
		}
		if err := ops.WriteConfig("key", nil, []byte(vkey)); err != nil {
			return nil, nil, fmt.Errorf("writing verifierkey: %v", err)
		}
	} else {
		if vkey != string(ovkey) {
			return nil, nil, fmt.Errorf("different key for name in verifierkey, new %s, old %s", vkey, string(ovkey))
		}
	}

	return sumdb.NewClient(ops), ops, nil
}

func (c *clientOps) ReadRemote(path string) ([]byte, error) {
	// log.Printf("client: ReadRemote %s", path)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("new http request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http transpaction: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http get: %v", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// ReadConfig reads and returns the content of the named configuration file.
// There are only a fixed set of configuration files.
//
// "key" returns a file containing the verifier key for the server.
//
// serverName + "/latest" returns a file containing the latest known
// signed tree from the server.
// To signal that the client wishes to start with an "empty" signed tree,
// ReadConfig can return a successful empty result (0 bytes of data).
func (c *clientOps) ReadConfig(file string) ([]byte, error) {
	// log.Printf("client: ReadConfig %s", file)

	p := filepath.Join(c.localDir, "config", file)
	buf, err := os.ReadFile(p)
	if err != nil && errors.Is(err, fs.ErrNotExist) && strings.HasSuffix(file, "/latest") {
		return nil, nil
	}
	return buf, err
}

// WriteConfig updates the content of the named configuration file,
// changing it from the old []byte to the new []byte.
// If the old []byte does not match the stored configuration,
// WriteConfig must return ErrWriteConflict.
// Otherwise, WriteConfig should atomically replace old with new.
// The "key" configuration file is never written using WriteConfig.
func (c *clientOps) WriteConfig(file string, old, new []byte) error {
	// log.Printf("client: WriteConfig %s", file)

	p := filepath.Join(c.localDir, "config", file)
	if old != nil {
		cur, err := c.ReadConfig(file)
		if err != nil {
			return fmt.Errorf("reading config: %v", err)
		}
		if !bytes.Equal(cur, old) {
			return sumdb.ErrWriteConflict
		}
	}
	os.MkdirAll(filepath.Dir(p), 0777)
	return os.WriteFile(p, new, 0666)
}

// ReadCache reads and returns the content of the named cache file.
// Any returned error will be treated as equivalent to the file not existing.
// There can be arbitrarily many cache files, such as:
//
//	serverName/lookup/pkg@version
//	serverName/tile/8/1/x123/456
func (c *clientOps) ReadCache(file string) ([]byte, error) {
	// log.Printf("client: Readcache %s", file)

	p := filepath.Join(c.localDir, "cache", file)
	return os.ReadFile(p)
}

// WriteCache writes the named cache file.
func (c *clientOps) WriteCache(file string, data []byte) {
	// log.Printf("client: WriteCache %s", file)

	p := filepath.Join(c.localDir, "cache", file)
	os.MkdirAll(filepath.Dir(p), 0777)
	if err := os.WriteFile(p, data, 0666); err != nil {
		// todo: should be able to return errors
		panic(fmt.Sprintf("write failed: %v", err))
	}
}

// Log prints the given log message (such as with log.Print)
func (c *clientOps) Log(msg string) {
	slog.Info(msg)
}

// SecurityError prints the given security error log message.
// The Client returns ErrSecurity from any operation that invokes SecurityError,
// but the return value is mainly for testing. In a real program,
// SecurityError should typically print the message and call log.Fatal or os.Exit.
func (c *clientOps) SecurityError(msg string) {
	slog.Error("transparency log security error", "err", msg)
	metricTlogSecurityError.Inc()
}
