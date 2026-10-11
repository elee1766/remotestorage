package filesystem_test

import (
	"testing"

	"anime.bike/remotestorage/contrib/storage/filesystem"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rstest"
)

func TestConformance(t *testing.T) {
	multi, err := filesystem.OpenMulti(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { multi.Close() })
	h := rstest.NewHarness(t, func(user string) (rsserver.StorageBackend, error) {
		return multi.User(user)
	})
	tg := h.Target("alice")
	tg.PrivateCaching = true
	rstest.Run(t, tg)
}
