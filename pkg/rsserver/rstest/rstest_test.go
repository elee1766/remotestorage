package rstest_test

import (
	"sync"
	"testing"

	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rsstorage/rsstorage_filesystem"
	"anime.bike/remotestorage/pkg/rsserver/rsstorage/rsstorage_inmemory"
	"anime.bike/remotestorage/pkg/rsserver/rstest"
	"github.com/spf13/afero"
)

func TestInMemory(t *testing.T) {
	var mu sync.Mutex
	users := map[string]*rsstorage_inmemory.Storage{}
	h := rstest.NewHarness(t, func(user string) (rsserver.StorageBackend, error) {
		mu.Lock()
		defer mu.Unlock()
		if users[user] == nil {
			users[user] = rsstorage_inmemory.New()
		}
		return users[user], nil
	}, func(b *rsserver.Builder) { b.WithMaxDocumentSize(1 << 16) })
	tg := h.Target("alice")
	tg.MaxDocumentSize = 1 << 16
	rstest.Run(t, tg)
}

func TestFilesystem(t *testing.T) {
	for name, fsys := range map[string]afero.Fs{"os": afero.NewBasePathFs(afero.NewOsFs(), t.TempDir()), "mem": afero.NewMemMapFs()} {
		t.Run(name, func(t *testing.T) {
			multi := rsstorage_filesystem.NewMulti(fsys, "/")
			h := rstest.NewHarness(t, func(user string) (rsserver.StorageBackend, error) {
				return multi.User(user)
			})
			rstest.Run(t, h.Target("alice"))
		})
	}
}
