// Package parallel runs a bounded number of calls at once.
package parallel

import "sync"

// Each calls fn for every index below n, at most limit at a time, and
// returns when all of them have. A limit below one is one.
func Each(n, limit int, fn func(i int)) {
	sem := make(chan struct{}, max(limit, 1))
	var wg sync.WaitGroup
	for i := range n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(i)
		})
	}
	wg.Wait()
}
