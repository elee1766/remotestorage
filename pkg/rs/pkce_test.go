package rs

import "testing"

func TestS256RFC7636Vector(t *testing.T) {
	// RFC 7636 Appendix B.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := S256Challenge(verifier); got != challenge {
		t.Fatalf("S256Challenge = %q, want %q", got, challenge)
	}
	if !ValidS256Challenge(challenge) || !VerifyS256(verifier, challenge) {
		t.Fatal("vector did not verify")
	}
	if VerifyS256(verifier[:42], S256Challenge(verifier[:42])) {
		t.Fatal("verifier shorter than 43 chars accepted")
	}
}
