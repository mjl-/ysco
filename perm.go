package main

import (
	"fmt"
	"os"
	"slices"
	"syscall"
)

func hasModeBit(p string, bit uint32, uid uint32, gids []uint32) (bool, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return false, err
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("unexpected stat type %T", fi.Sys())
	}
	if stat.Uid == uid {
		return uint32(stat.Mode>>6)&bit != 0, nil
	}
	if slices.Contains(gids, stat.Gid) {
		return uint32(stat.Mode>>3)&bit != 0, nil
	}
	return uint32(stat.Mode)&bit != 0, nil
}
