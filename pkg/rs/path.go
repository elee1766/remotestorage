package rs

import (
	"errors"
	"strings"
)

// ErrInvalidPath is returned for paths that the protocol does not allow.
var ErrInvalidPath = errors.New("invalid path")

// ValidatePath checks a path relative to the storage root. It must start
// with "/", and every item name must be non-empty, must not be "." or "..",
// and must not contain a null character. Folder paths end in "/".
func ValidatePath(p string) error {
	if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
		return ErrInvalidPath
	}
	if p == "/" {
		return nil
	}
	segs := strings.Split(strings.TrimSuffix(p[1:], "/"), "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return ErrInvalidPath
		}
	}
	return nil
}

// IsFolderPath reports whether p names a folder.
func IsFolderPath(p string) bool { return strings.HasSuffix(p, "/") }

// SplitModule returns the scope module of a storage path and whether it is in
// the public subtree. For "/contacts/a" it returns ("contacts", false), for
// "/public/contacts/a" ("contacts", true). The root folder "/" and the
// "/public/" folder have an empty module.
func SplitModule(p string) (module string, isPublic bool) {
	rest := strings.TrimPrefix(p, "/")
	first, after, hasSlash := strings.Cut(rest, "/")
	if first == PublicModule && hasSlash {
		isPublic = true
		first, _, hasSlash = strings.Cut(after, "/")
	}
	if !hasSlash {
		// A document directly under the root (or under /public/) has no module.
		return "", isPublic
	}
	return first, isPublic
}

// ParentPath returns the folder containing p ("/a/b" -> "/a/", "/a/" -> "/").
// The parent of "/" is "".
func ParentPath(p string) string {
	if p == "/" || p == "" {
		return ""
	}
	t := strings.TrimSuffix(p, "/")
	i := strings.LastIndex(t, "/")
	return t[:i+1]
}

// BaseName returns the item name of p, with a trailing "/" for folders.
func BaseName(p string) string {
	if p == "/" {
		return ""
	}
	return p[len(ParentPath(p)):]
}
