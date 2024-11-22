//go:build linux

package main

import "syscall"

func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid:     true,
		AmbientCaps: config.Process.ambientCaps,
	}
}
