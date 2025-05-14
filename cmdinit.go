package main

import (
	"errors"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mjl-/sconf"
)

func cmdInit(args []string) {
	if len(args) != 1 {
		log.Fatalf("need exactly one parameter, a package path")
	}

	if _, err := os.Stat("ys"); err == nil {
		log.Fatalf("directory ys already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("checking directory ys: %v", err)
	}

	// Find module path and latest version.
	pkgPath := args[0]
	modPath := pkgPath
	var modVersion string
	for {
		versions, err := lookupModuleVersions(slog.Default(), modPath)
		if err != nil {
			// todo: should probably check for "does not exist" vs "other error"
			t := strings.Split(modPath, "/")
			if len(t) <= 1 {
				log.Fatalf("no module found for package path %q", pkgPath)
			}
			modPath = strings.Join(t[:len(t)-1], "/")
			continue
		}
		if len(versions) == 0 {
			log.Fatalf("no stable version yet for module %q", modPath)
		}
		modVersion = versions[0].Full
		break
	}

	// Find latest Go toolchain.
	tc, err := lookupToolchainVersions(slog.Default())
	xcheckf(err, "looking up go toolchains")

	pkgDir := strings.TrimPrefix(pkgPath, modPath)
	if pkgDir == "" {
		pkgDir = "/"
	}

	// Prepare the gobuild tlog verifier cache directory.
	err = os.Mkdir("ys", 0700)
	xcheckf(err, "mkdir ys")
	err = os.Mkdir("ys/gobuildverifiercache", 0700)
	xcheckf(err, "mkdir ys/gobuildverifiercache")

	tlog.client, tlog.ops, err = newClient(defaults.Gobuild.VerifierKey, defaults.Gobuild.BaseURL, "ys/gobuildverifiercache")
	xcheckf(err, "new tlog client")

	// Download new file.
	log.Printf("downloading %s@%s%s...", modPath, modVersion, pkgDir)
	bs := buildSpec{
		Mod:       modPath,
		Version:   modVersion,
		Dir:       pkgDir,
		Goos:      runtime.GOOS,
		Goarch:    runtime.GOARCH,
		Goversion: tc.Cur,
		Stripped:  true,
	}

	_, data, err := tlog.client.Lookup(bs.String())
	xcheckf(err, "looking up binary at gobuild")
	xbr, err := parseRecord(data)
	xcheckf(err, "parsing gobuild record")
	br := *xbr
	if bs != br.buildSpec {
		log.Fatalf("tlog returned different buildspec %v, requested %v", br.buildSpec, bs)
	}
	url := downloadURL(br)

	versionName := downloadFilename(br)
	f, err := os.CreateTemp(".", versionName+".*")
	xcheckf(err, "creating temp file")

	err = gobuildFetch(f, url, br.Sum)
	xcheckf(err, "downloading binary")

	err = f.Chmod(0755)
	xcheckf(err, "chmod temporary file")

	tmpName := f.Name()
	err = f.Close()
	xcheckf(err, "closing binary")

	err = os.Rename(tmpName, versionName)
	xcheckf(err, "rename temporary to final binary filename")

	shortname := filepath.Base(pkgPath)
	if runtime.GOOS == "windows" {
		shortname += ".exe"
	}
	err = os.Symlink(versionName, shortname)
	xcheckf(err, "symlink full binary filename to short name")

	password := genrandom()
	err = os.WriteFile("ys/password.txt", []byte(password+"\n"), 0600)
	xcheckf(err, "writing password file")

	ysDir = "ys"
	state = &State{}
	err = state.write()
	xcheckf(err, "writing state.json")

	cf, err := os.Create("ys/ysco.conf")
	xcheckf(err, "create config file")
	cfg := Config{
		LogLevel: "info",
		AuthFile: "ys/password.txt",
	}
	err = sconf.Write(cf, cfg)
	xcheckf(err, "writing config file")
	err = cf.Close()
	xcheckf(err, "closing config file")

	if filepath.Dir(os.Args[0]) == "." && filepath.Base(os.Args[0]) != "ysco" {
		err := os.Symlink(os.Args[0], "ysco")
		xcheckf(err, "creating ysco symlink")
	}

	log.Printf("initialized ys/, created symlinks ysco and %s, admin interface will be at http://admin:%s@localhost:1234/ after starting:", shortname, password)
	log.Printf("./ysco run -addr localhost:1234 ./%s # [flags]", shortname)
}
