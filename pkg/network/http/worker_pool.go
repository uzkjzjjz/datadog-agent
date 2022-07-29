package http

import "sync"

type workerPool struct {
	size      int
	jobs      chan func()
	waitGroup sync.WaitGroup
	once      sync.Once
}

func newWorkerPool(size int) *workerPool {
	pool := &workerPool{
		size: size,
		jobs: make(chan func()),
	}

	for i := 0; i < size; i++ {
		pool.waitGroup.Add(1)
		go func() {
			defer pool.waitGroup.Done()
			for f := range pool.jobs {
				f()
			}
		}()
	}

	return pool
}

func (wp *workerPool) Do(f func()) {
	wp.jobs <- f
}

func (wp *workerPool) Stop() {
	wp.once.Do(func() {
		close(wp.jobs)
		wp.waitGroup.Wait()

	})
}
