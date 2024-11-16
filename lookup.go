package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

func lookupToolchainVersions(log *slog.Logger) (rtc Toolchains, rerr error) {
	defer func() {
		log.Debug("result of looking up toolchains", "modpath", "golang.org/toolchain", "toolchains", rtc, "err", rerr)
	}()

	err := fmt.Errorf("no monitor mechanisms")
	for _, m := range monitorParsed {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var tc Toolchains
		switch m {
		case "dns":
			tc, err = LookupToolchains(ctx, monitorDNS)
		case "goproxy":
			goproxy := monitorGoProxy
			if monitorGoProxyToolchain != "" {
				goproxy = monitorGoProxyToolchain
			}
			tc, err = lookupToolchainVersionGoProxy(ctx, goproxy)
		default:
			return Toolchains{}, fmt.Errorf("unknown monitor mechanism %q", m)
		}
		if err == nil {
			return tc, nil
		}
		metricMonitorError.Inc()
		log.Error("looking up toolchains", "err", err, "monitor", m)
	}
	return Toolchains{}, err
}

func lookupModuleVersions(log *slog.Logger, modpath string) (rversions []Version, rerr error) {
	defer func() {
		log.Debug("result of looking up module", "modpath", modpath, "versions", rversions, "err", rerr)
	}()

	err := fmt.Errorf("no monitor mechanisms")
	for _, m := range monitorParsed {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var versions []Version
		switch m {
		case "dns":
			versions, err = LookupModule(ctx, monitorDNS, modpath)
		case "goproxy":
			versions, err = lookupModuleVersionsGoProxy(ctx, monitorGoProxy, modpath)
		default:
			return nil, fmt.Errorf("unknown monitor mechanism %q", m)
		}
		if err == nil {
			return versions, nil
		}
		metricMonitorError.Inc()
		log.Error("looking up module", "err", err, "monitor", m)
	}
	return nil, err
}
