package main

import (
	"log/slog"
	"testing"
	"time"
)

func TestPolicyPickVersion(t *testing.T) {
	log := slog.Default()

	test := func(pol, poltc string, tc Toolchains, vers Version, govers string, versions []Version, expVers Version, expGovers string, expUpdate, expFoundMajor bool) {
		t.Helper()
		nvers, ngovers, update, foundMajor := policyPickVersion(log, VersionPolicy(pol), GoVersionPolicy(poltc), tc, vers, govers, govers, versions)
		if nvers != expVers || ngovers != expGovers || update != expUpdate || foundMajor != expFoundMajor {
			t.Fatalf("got %v %v %v %v, expected %v %v %v %v", nvers, ngovers, update, foundMajor, expVers, expGovers, expUpdate, expFoundMajor)
		}
	}

	xversion := func(s string) Version {
		t.Helper()
		vers, err := parseVersion(s, time.Time{})
		if err != nil {
			t.Fatalf("parsing version %q: %v", s, err)
		}
		return vers
	}
	xversions := func(l ...string) (r []Version) {
		for _, s := range l {
			r = append(r, xversion(s))
		}
		return r
	}

	tc0 := Toolchains{
		Prev: "go1.22.8",
		Cur:  "go1.23.2",
	}
	tc1 := Toolchains{
		Prev: "go1.22.9",
		Cur:  "go1.23.3",
	}
	test("manual", "manual", tc0, xversion("v0.1.2"), "go1.23.2", xversions("v0.1.3"), xversion("v0.1.2"), "go1.23.2", false, true)
	test("manual", "follow", tc0, xversion("v0.1.2"), "go1.23.2", xversions("v0.1.3"), xversion("v0.1.2"), "go1.23.2", false, true)
	test("manual", "follow", tc1, xversion("v0.1.2"), "go1.23.2", xversions("v0.1.3"), xversion("v0.1.2"), "go1.23.3", true, true)
	test("patch", "follow", tc0, xversion("v0.1.2"), "go1.23.2", xversions("v0.1.2"), xversion("v0.1.2"), "go1.23.2", false, true)         // No change.
	test("patch", "follow", tc0, xversion("v0.1.2"), "go1.23.2", xversions("v0.1.3"), xversion("v0.1.3"), "go1.23.2", true, true)          // New module.
	test("patch", "follow", tc1, xversion("v0.1.2"), "go1.23.2", xversions("v0.1.3"), xversion("v0.1.3"), "go1.23.3", true, true)          // New module and toolchain.
	test("patch", "follow", tc1, xversion("v0.1.3"), "go1.23.3", xversions("v0.1.3"), xversion("v0.1.3"), "go1.23.3", false, true)         // New toolchain.
	test("patch", "follow", tc1, xversion("v0.1.2"), "go1.22.8", xversions("v0.1.3"), xversion("v0.1.3"), "go1.23.3", true, true)          // To new toolchain for new version.
	test("patch", "follow", tc1, xversion("v0.1.2"), "go1.21.8", xversions("v0.1.2"), xversion("v0.1.2"), "go1.22.9", true, true)          // To supported toolchain.
	test("patch", "supported", tc1, xversion("v0.1.2"), "go1.21.8", xversions("v0.1.2"), xversion("v0.1.2"), "go1.22.9", true, true)       // To supported toolchain.
	test("patch", "minor", tc1, xversion("v0.1.2"), "go1.22.8", xversions("v0.1.2"), xversion("v0.1.2"), "go1.23.3", true, true)           // Update minor toolchains.
	test("patch", "follow", tc0, xversion("v0.0.2"), "go1.22.8", xversions("v0.1.2"), xversion("v0.0.2"), "go1.22.8", false, true)         // Don't update minor version.
	test("minor", "follow", tc0, xversion("v0.0.2"), "go1.22.8", xversions("v0.1.2"), xversion("v0.1.2"), "go1.23.2", true, true)          // Update minor version.
	test("manual", "manual", tc0, xversion("v0.0.2"), "go1.22.8", xversions("v1.1.2"), xversion("v0.0.2"), "go1.22.8", false, false)       // No major version.
	test("manual", "follow", tc1, xversion("v0.0.2"), "go1.22.8", xversions("v1.1.2"), xversion("v0.0.2"), "go1.22.9", true, false)        // No major, still toolchain update.
	test("patch", "follow", tc1, xversion("v0.0.3-pre"), "go1.22.9", xversions("v0.0.3"), xversion("v0.0.3"), "go1.23.3", true, true)      // Update from prerelease to actual.
	test("manual", "follow", tc1, xversion("v0.0.3-pre"), "go1.22.8", xversions("v0.0.3"), xversion("v0.0.3-pre"), "go1.22.9", true, true) // Update toolchain also while in prerelease.
}
