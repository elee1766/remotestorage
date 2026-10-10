package rs

import (
	"fmt"
	"regexp"
	"strings"
)

// Scope represents an access scope for RemoteStorage
type Scope struct {
	Module string
	Access AccessLevel
}

// AccessLevel represents read or read/write access
type AccessLevel string

const (
	ReadAccess      AccessLevel = "r"
	ReadWriteAccess AccessLevel = "rw"
)

func (s Scope) String() string { return s.Module + ":" + string(s.Access) }

var moduleRe = regexp.MustCompile(`^[a-z0-9_-]+$`)

// ValidModule reports whether name may be used as a scope module.
// "*" is allowed, "public" is reserved.
func ValidModule(name string) bool {
	return name == "*" || (name != PublicModule && moduleRe.MatchString(name))
}

// ParseScope parses "<module>:<r|rw>".
func ParseScope(s string) (Scope, error) {
	module, level, ok := strings.Cut(s, ":")
	if !ok {
		return Scope{}, fmt.Errorf("invalid scope %q", s)
	}
	module = strings.ToLower(module)
	if !ValidModule(module) {
		return Scope{}, fmt.Errorf("invalid scope module %q", module)
	}
	switch AccessLevel(level) {
	case ReadAccess, ReadWriteAccess:
		return Scope{Module: module, Access: AccessLevel(level)}, nil
	}
	return Scope{}, fmt.Errorf("invalid scope access level %q", level)
}

// ParseScopes parses a space separated OAuth scope string. Invalid entries
// are reported in invalid. Duplicate modules are merged, keeping the widest access.
func ParseScopes(s string) (scopes []Scope, invalid []string) {
	idx := map[string]int{}
	for _, part := range strings.Fields(s) {
		sc, err := ParseScope(part)
		if err != nil {
			invalid = append(invalid, part)
			continue
		}
		if i, ok := idx[sc.Module]; ok {
			if sc.Access == ReadWriteAccess {
				scopes[i].Access = ReadWriteAccess
			}
			continue
		}
		idx[sc.Module] = len(scopes)
		scopes = append(scopes, sc)
	}
	return scopes, invalid
}

// FormatScopes joins scopes into a space separated OAuth scope string.
func FormatScopes(scopes []Scope) string {
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = s.String()
	}
	return strings.Join(parts, " ")
}

// CheckScopeAccess reports whether scopes grant access to module.
// module is the first path segment after the storage root (or after
// "/public/"); it is empty for the root folder and the "/public/" folder,
// which only '*' scopes can access. Public document reads are handled by the
// authorizer, not here.
func CheckScopeAccess(scopes []Scope, module string, isRead bool) bool {
	for _, scope := range scopes {
		if scope.Module != "*" && scope.Module != module {
			continue
		}
		if scope.Access == ReadWriteAccess || (scope.Access == ReadAccess && isRead) {
			return true
		}
	}
	return false
}
