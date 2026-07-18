package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateLimiterPerIP(t *testing.T) {
	rl := newRateLimiter(rate.Every(time.Hour), 3) // burst 3, effectively no refill
	for i := 0; i < 3; i++ {
		if !rl.limiterFor("1.2.3.4").Allow() {
			t.Fatalf("request %d from an IP should be allowed within burst", i)
		}
	}
	if rl.limiterFor("1.2.3.4").Allow() {
		t.Fatal("request beyond burst should be denied")
	}
	if !rl.limiterFor("5.6.7.8").Allow() {
		t.Fatal("a different IP should have its own budget")
	}
}

func TestAuthEndpointRateLimited(t *testing.T) {
	s := NewServer(Config{}, nil)
	h := s.Handler()

	got429 := false
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected a 429 after exceeding the auth rate limit")
	}
}
