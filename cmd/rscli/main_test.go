package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestImplicitCallbackRejectsQueryTokenAndSecuresPOST(t *testing.T) {
	results := make(chan implicitCallbackResult, 1)
	handler := implicitCallbackHandler("expected-state", "127.0.0.1:8765", results)

	request := httptest.NewRequest(http.MethodPost, "/callback?access_token=stolen", strings.NewReader("state=expected-state&access_token=posted"))
	request.Host = "localhost:8765"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("callback with query token returned status %d, want %d", response.Code, http.StatusNotFound)
	}
	select {
	case result := <-results:
		t.Fatalf("query callback delivered a result: %+v", result)
	default:
	}

	for _, body := range []string{
		"state=wrong-state&access_token=attacker",
		"access_token=attacker",
		strings.Repeat("x", 9<<10),
	} {
		request = httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(body))
		request.Host = "localhost:8765"
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("invalid callback body returned status %d, want %d", response.Code, http.StatusBadRequest)
		}
		select {
		case result := <-results:
			t.Fatalf("invalid callback delivered a result: %+v", result)
		default:
		}
	}

	request = httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader("state=expected-state&access_token=legitimate"))
	request.Host = "localhost:8765"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid callback returned status %d, want %d", response.Code, http.StatusOK)
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	select {
	case result := <-results:
		if result.token != "legitimate" || result.err != nil {
			t.Fatalf("callback result = %+v, want legitimate token", result)
		}
	default:
		t.Fatal("valid callback did not deliver a result")
	}

	request = httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader("state=expected-state&access_token=attacker"))
	request.Host = "attacker.example:8765"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("callback with untrusted Host returned status %d, want %d", response.Code, http.StatusBadRequest)
	}
}
