package parallel

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestEach(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, 3, 50} {
		const n = 20
		var running, peak atomic.Int64
		done := make([]bool, n)
		Each(n, limit, func(i int) {
			now := running.Add(1)
			defer running.Add(-1)
			for {
				seen := peak.Load()
				if now <= seen || peak.CompareAndSwap(seen, now) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			done[i] = true
		})
		for i, ok := range done {
			if !ok {
				t.Fatalf("limit %d: index %d was not called", limit, i)
			}
		}
		if got := peak.Load(); got > int64(max(limit, 1)) {
			t.Fatalf("limit %d: %d calls at once", limit, got)
		}
	}
	Each(0, 4, func(int) { t.Fatal("called with nothing to do") })
}
