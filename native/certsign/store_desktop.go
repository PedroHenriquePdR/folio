//go:build windows || darwin

package main

import (
	"context"
	"runtime"

	"github.com/sukujgrg/go-certstore"
)

// go.mjs applies Folio's cache-only chain lookup to the pinned OS backends.
// An ordinary unpatched build must never silently enable network fetching.
const _ = certstore.FolioOfflineChains

func openSystemStore(ctx context.Context, _ string) (certstore.Store, error) {
	if runtime.GOOS == "windows" {
		return certstore.Open(ctx, certstore.WithBackend(certstore.BackendWindows),
			certstore.WithWindowsStoreLocation(certstore.WindowsStoreCurrentUser), certstore.WithWindowsStoreName("MY"))
	}
	return certstore.Open(ctx, certstore.WithBackend(certstore.BackendDarwin))
}
