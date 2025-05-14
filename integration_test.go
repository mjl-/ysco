//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/mjl-/sconf"
)

func urlValues(args ...string) url.Values {
	uv := url.Values{}
	for i := 0; i < len(args); i += 2 {
		uv.Set(args[i], args[i+1])
	}
	return uv
}

// Start ysco, running webserver, in the background. We will talk to it over HTTP,
// making it update, and discover new updates.
func TestIntegration(t *testing.T) {
	tcheck := func(err error, msg string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %s", msg, err)
		}
	}

	tcompare := func(got, exp any) {
		t.Helper()
		if !reflect.DeepEqual(got, exp) {
			t.Fatalf("got %v, expected %v", got, exp)
		}
	}

	err := os.Mkdir("ys", 0700)
	tcheck(err, "mkdir ys")

	config := Config{
		LogLevel: "debug",
		AuthFile: "ys/password.txt",
		Monitor: ConfigMonitor{
			Methods:          []MonitorMethod{MonitorGoProxy},
			GoProxy:          "http://goproxy:2080",
			GoProxyToolchain: "https://proxy.golang.org/cached-only/",
			Delay:            3 * time.Second,
		},
		Update: ConfigUpdate{
			Delay:  time.Hour,
			Jitter: 3 * time.Second,
		},
		Gobuild: ConfigGobuild{
			VerifierKey: "localhost+7f833345+ARbs+7AvMjM6pK7XBKzOYcR4Ko6TXOO0TvTxBnYHKgJi",
			BaseURL:     "http://gobuild:4080/tlog",
		},
	}
	var b bytes.Buffer
	err = sconf.Write(&b, config)
	tcheck(err, "generate config")
	err = os.WriteFile("ys/ysco.conf", b.Bytes(), 0600)
	tcheck(err, "write config")
	err = os.WriteFile("ys/password.txt", []byte("test1234\n"), 0600)
	tcheck(err, "write password.txt")

	fmt.Println("# Starting ysco")
	cmd := exec.Command("sh", "-c", "./ysco-v0.9.9 run -user 1000 -groups 1000 -addr 127.0.0.1:8523 ./webserver")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	tcheck(err, "start ysco")

	defer func() {
		fmt.Println("# Sending sigterm to ysco for cleanup")
		err := cmd.Process.Signal(syscall.SIGTERM)
		tcheck(err, "sigterm to ysco")

		fmt.Println("# Wait for ysco to finish.")
		cmd.Wait() // Will return with error that it was killed.
		fmt.Println("# Cleanup done.")
	}()

	// Try connecting for up to 3s for ysco to get started.
	t0 := time.Now()
	for {
		if time.Since(t0) > 3*time.Second {
			t.Fatalf("ysco did not get up within 3s")
		}

		conn, err := net.Dial("tcp", "127.0.0.1:8523")
		if err == nil {
			conn.Close()
			break
		}

		time.Sleep(time.Second / 10)
	}

	httpclient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Get current state.
	resp, err := httpclient.Get("http://admin:test1234@127.0.0.1:8523")
	tcheck(err, "get html")
	tcompare(resp.StatusCode, http.StatusOK)
	err = resp.Body.Close()
	tcheck(err, "close http body")

	var state indexArgs

	getState := func() {
		t.Helper()

		resp, err = httpclient.Get("http://admin:test1234@127.0.0.1:8523/json")
		tcheck(err, "get json")
		tcompare(resp.StatusCode, http.StatusOK)
		state = indexArgs{}
		err = json.NewDecoder(resp.Body).Decode(&state)
		tcheck(err, "decoding json")
	}

	getState()
	tcompare(state.SvcVersion, "v0.0.5")
	tcompare(state.SvcGoVersion, "go1.24.2")
	tcompare(state.SelfVersion, "v0.9.9")
	tcompare(state.SelfGoVersion, "go1.24.2")

	fmt.Println("# Updating service to v0.0.4, go1.23.8.")
	resp, err = httpclient.PostForm("http://admin:test1234@127.0.0.1:8523", urlValues("command", "update", "which", "svc", "version", "v0.0.4", "goversion", "go1.23.8"))
	tcheck(err, "update svc")
	tcompare(resp.StatusCode, http.StatusSeeOther)
	err = resp.Body.Close()
	tcheck(err, "close http body")

	time.Sleep(time.Second)
	getState()
	tcompare(state.SvcVersion, "v0.0.4")
	tcompare(state.SvcGoVersion, "go1.23.8")

	fmt.Println("# Checking for updates, should find v0.0.5.")
	resp, err = httpclient.PostForm("http://admin:test1234@127.0.0.1:8523", urlValues("command", "check"))
	tcheck(err, "check for updates")

	getState()
	tcompare(len(state.Scheduled), 2) // To v0.0.5 again, and new Go toolchain for ysco.

	fmt.Println("# Waiting for rollback period to expire")
	time.Sleep(6 * time.Second)

	fmt.Println("# Updating service to v0.0.5, go1.24.2.")
	resp, err = httpclient.PostForm("http://admin:test1234@127.0.0.1:8523", urlValues("command", "update", "which", "svc", "version", "v0.0.5", "goversion", "go1.24.2"))
	tcheck(err, "update svc")
	tcompare(resp.StatusCode, http.StatusSeeOther)
	err = resp.Body.Close()
	tcheck(err, "close http body")

	time.Sleep(time.Second)
	getState()
	tcompare(state.SvcVersion, "v0.0.5")
	tcompare(state.SvcGoVersion, "go1.24.2")

	fmt.Println("# Waiting for rollback period to expire")
	time.Sleep(6 * time.Second)

	fmt.Println("# Updating self to v0.9.8 go1.24.2.")
	resp, err = httpclient.PostForm("http://admin:test1234@127.0.0.1:8523", urlValues("command", "update", "which", "self", "version", "v0.9.8", "goversion", "go1.24.2"))
	tcheck(err, "update self")
	tcompare(resp.StatusCode, http.StatusSeeOther)
	err = resp.Body.Close()
	tcheck(err, "close http body")

	time.Sleep(time.Second)
	getState()
	tcompare(state.SelfVersion, "v0.9.8")
	tcompare(state.SelfGoVersion, "go1.24.2")

	fmt.Println("# Waiting for rollback period to expire")
	time.Sleep(6 * time.Second)

	fmt.Println("# Updating self to v0.9.9 go1.24.2.")
	resp, err = httpclient.PostForm("http://admin:test1234@127.0.0.1:8523", urlValues("command", "update", "which", "self", "version", "v0.9.9", "goversion", "go1.24.2"))
	tcheck(err, "update self")
	tcompare(resp.StatusCode, http.StatusSeeOther)
	err = resp.Body.Close()
	tcheck(err, "close http body")

	time.Sleep(time.Second)
	getState()
	tcompare(state.SelfVersion, "v0.9.9")
	tcompare(state.SelfGoVersion, "go1.24.2")

	fmt.Println("# Waiting for rollback period to expire")
	time.Sleep(6 * time.Second)

	fmt.Println("# Updating self to v0.9.8 go1.23.8.")
	resp, err = httpclient.PostForm("http://admin:test1234@127.0.0.1:8523", urlValues("command", "update", "which", "self", "version", "v0.9.8", "goversion", "go1.23.8"))
	tcheck(err, "update self")
	tcompare(resp.StatusCode, http.StatusSeeOther)
	err = resp.Body.Close()
	tcheck(err, "close http body")

	time.Sleep(time.Second)
	getState()
	tcompare(state.SelfVersion, "v0.9.8")
	tcompare(state.SelfGoVersion, "go1.23.8")

	fmt.Println("# Waiting for rollback period to expire")
	time.Sleep(6 * time.Second)

	fmt.Println("# Done.")
}
