package readiness

import "sync"

type Gate struct {
	mu     sync.RWMutex
	checks map[string]string
}

func New(names ...string) *Gate {
	g := &Gate{checks: map[string]string{}}
	for _, n := range names {
		g.checks[n] = "unverified"
	}
	return g
}
func (g *Gate) Set(name, problem string) { g.mu.Lock(); defer g.mu.Unlock(); g.checks[name] = problem }
func (g *Gate) Ready() (bool, map[string]string) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]string, len(g.checks))
	ok := true
	for k, v := range g.checks {
		out[k] = v
		if v != "" {
			ok = false
		}
	}
	return ok, out
}
