package controlplane

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	rlCleanupEvery = 5 * time.Minute
	rlStaleAfter   = 10 * time.Minute
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiter is a per-IP token bucket. Stale entries are evicted lazily under
// the lock, so it needs no background goroutine.
type rateLimiter struct {
	mu          sync.Mutex
	visitors    map[string]*visitor
	rate        rate.Limit
	burst       int
	lastCleanup time.Time
}

func newRateLimiter(r rate.Limit, burst int) *rateLimiter {
	return &rateLimiter{visitors: make(map[string]*visitor), rate: r, burst: burst, lastCleanup: time.Now()}
}

func (rl *rateLimiter) limiterFor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if time.Since(rl.lastCleanup) > rlCleanupEvery {
		for k, v := range rl.visitors {
			if time.Since(v.lastSeen) > rlStaleAfter {
				delete(rl.visitors, k)
			}
		}
		rl.lastCleanup = time.Now()
	}

	v, ok := rl.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	return v.limiter
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.limiterFor(clientIP(r)).Allow() {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP resolves the real client address from trusted proxy headers, with fallbacks.
// Cloudflare's CF-Connecting-IP and Traefik's X-Real-IP are set authoritatively by the proxy;
// leftmost X-Forwarded-For is a last resort.
func clientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
