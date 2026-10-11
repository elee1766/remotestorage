package rstest_test

import (
	"sync"
	"testing"

	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rstest"
)

func TestMemoryStorage(t *testing.T) {
	var mu sync.Mutex
	users := map[string]*rstest.MemoryStorage{}
	h := rstest.NewHarness(t, func(user string) (rsserver.StorageBackend, error) {
		mu.Lock()
		defer mu.Unlock()
		if users[user] == nil {
			users[user] = rstest.NewMemoryStorage()
		}
		return users[user], nil
	}, func(b *rsserver.Builder) { b.WithMaxDocumentSize(1 << 16) })
	tg := h.Target("alice")
	tg.MaxDocumentSize = 1 << 16
	tg.PrivateCaching = true
	rstest.Run(t, tg)
}

// TestPlainCacheControl runs the suite with the spec-check compatible setting.
func TestPlainCacheControl(t *testing.T) {
	store := rstest.NewMemoryStorage()
	h := rstest.NewHarness(t, func(user string) (rsserver.StorageBackend, error) {
		return store, nil
	}, func(b *rsserver.Builder) { b.WithCacheControl(rsserver.PlainCacheControl) })
	tg := h.Target("alice")
	tg.OtherUserRoot = ""
	rstest.Run(t, tg)
}
