package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexServed(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type=%q", ct)
	}
	if !strings.Contains(w.Body.String(), "routerd") {
		t.Fatal("index does not reference routerd")
	}
}

func TestAssetsServed(t *testing.T) {
	for _, p := range []string{"/app.js", "/style.css"} {
		w := httptest.NewRecorder()
		Handler().ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 || w.Body.Len() < 100 {
			t.Fatalf("%s: status=%d len=%d", p, w.Code, w.Body.Len())
		}
	}
}

func TestUnknownPathAndMethod(t *testing.T) {
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest("GET", "/nope.xyz", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown path status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d", w.Code)
	}
}

func TestNoTraversal(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/../go.mod", nil)
	r.URL.Path = "/../go.mod"
	Handler().ServeHTTP(w, r)
	if w.Code == 200 && strings.Contains(w.Body.String(), "module router") {
		t.Fatal("traversal leaked go.mod")
	}
}
