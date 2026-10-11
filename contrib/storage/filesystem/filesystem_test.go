package filesystem_test

import (
	"testing"

	"anime.bike/remotestorage/contrib/storage/filesystem"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rstest"
	"github.com/spf13/afero"
)

func TestConformance(t *testing.T) {
	for name, fsys := range map[string]afero.Fs{"os": afero.NewBasePathFs(afero.NewOsFs(), t.TempDir()), "mem": afero.NewMemMapFs()} {
		t.Run(name, func(t *testing.T) {
			multi := filesystem.NewMulti(fsys, "/")
			h := rstest.NewHarness(t, func(user string) (rsserver.StorageBackend, error) {
				return multi.User(user)
			})
			tg := h.Target("alice")
			tg.PrivateCaching = true
			rstest.Run(t, tg)
		})
	}
}
