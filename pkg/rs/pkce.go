package rs

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

// PKCEMethodS256 is the only code_challenge_method servers MUST support (spec §10.1).
const PKCEMethodS256 = "S256"

var (
	s256ChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// RFC 7636 §4.1: 43-128 unreserved characters.
	codeVerifierRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// S256Challenge returns BASE64URL(SHA256(verifier)) without padding.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidS256Challenge reports whether challenge has the shape of an S256 digest.
func ValidS256Challenge(challenge string) bool {
	return s256ChallengeRe.MatchString(challenge)
}

// VerifyS256 reports whether verifier is well formed and matches challenge.
func VerifyS256(verifier, challenge string) bool {
	if !codeVerifierRe.MatchString(verifier) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(S256Challenge(verifier)), []byte(challenge)) == 1
}
