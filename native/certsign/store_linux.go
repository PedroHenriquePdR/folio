package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sukujgrg/go-certstore"
)

func openSystemStore(ctx context.Context, password string) (certstore.Store, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil, errors.New("no home directory")
	}
	// Match Chromium's GetDefaultNSSConfigDirectory, including legacy precedence.
	dir := filepath.Join(home, ".pki", "nssdb")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		data := os.Getenv("XDG_DATA_HOME")
		if !filepath.IsAbs(data) {
			data = filepath.Join(home, ".local", "share")
		}
		dir = filepath.Join(data, "pki", "nssdb")
	}
	for _, db := range []string{"cert9.db", "key4.db"} {
		if info, err := os.Stat(filepath.Join(dir, db)); err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("NSS shared database unavailable")
		}
	}
	// Use only OS-installed softokn. Never load modules from browser profiles
	// or from the current directory. softokn opens the selected DB read-only.
	multiarch := map[string]string{"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu", "386": "i386-linux-gnu", "arm": "arm-linux-gnueabihf"}
	dirs := []string{"/usr/lib64", "/usr/lib"}
	if arch, ok := multiarch[runtime.GOARCH]; ok {
		dirs = append([]string{filepath.Join("/usr/lib", arch)}, dirs...)
	}
	for _, systemDir := range dirs {
		module := filepath.Join(systemDir, "libsoftokn3.so")
		if info, err := os.Stat(module); err == nil && info.Mode().IsRegular() {
			options := []certstore.Option{certstore.WithBackend(certstore.BackendNSS), certstore.WithNSSProfileDir(dir), certstore.WithNSSModule(module)}
			if password != "" {
				options = append(options, certstore.WithCredentialPrompt(func(certstore.PromptInfo) ([]byte, error) { return []byte(password), nil }))
			}
			return certstore.Open(ctx, options...)
		}
	}
	return nil, errors.New("NSS system module unavailable")
}
