package main

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

//go:embed licenses/*
var licensesFsys embed.FS

func licensesWrite(dst io.Writer) error {
	copyFile := func(p string) error {
		f, err := licensesFsys.Open(p)
		if err != nil {
			return fmt.Errorf("open license file: %v", err)
		}
		if _, err := io.Copy(dst, f); err != nil {
			return fmt.Errorf("copy license file: %v", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close license file: %v", err)
		}
		return nil
	}

	err := fs.WalkDir(licensesFsys, "licenses", func(path string, d fs.DirEntry, err error) error {
		if !d.Type().IsRegular() {
			return nil
		}
		if _, err := fmt.Fprintf(dst, "\n\n# %s\n\n", strings.TrimPrefix(path, "licenses/")); err != nil {
			return err
		}
		return copyFile(path)
	})
	if err != nil {
		return fmt.Errorf("walk licenses: %v", err)
	}
	return nil
}
