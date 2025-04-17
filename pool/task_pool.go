package pool

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var (
	panicBuffLen        = 2048
	errTaskRunningPanic = errors.New("zkit: Task 运行时异常")
)

// Task 代表一个任务
type Task interface {
	// Run 执行任务
	// 如果 ctx 设置了超时时间，那么实现者需要自己决定是否进行超时控制
	Run(ctx context.Context) error
}

type taskWrapper struct {
	t Task
}

func (tw *taskWrapper) Run(ctx context.Context) (err error) {
	defer func() {
		// 处理 panic
		if r := recover(); r != nil {
			buf := make([]byte, panicBuffLen)
			buf = buf[:runtime.Stack(buf, false)]
			err = fmt.Errorf("%w：%s", errTaskRunningPanic, fmt.Sprintf("[PANIC]:\t%+v\n%s\n", r, buf))
		}
	}()
	return tw.t.Run(ctx)
}

type worker struct {
	tasks chan Task
	quit  chan struct{}
	id    int
}

// newWorker returns a new worker
func newWorker(id int) *worker {
	return &worker{
		tasks: make(chan Task),
		quit:  make(chan struct{}),
		id:    id,
	}
}

// start starts a worker to begin working
func (w *worker) start() {
	go func() {
		for {
			select {
			case t := <-w.tasks:
				tr := &taskWrapper{t: t}
				tr.Run(context.Background())
			case <-w.quit:
				return
			}
		}
	}()
}

// stop stops a worker
func (w *worker) stop() {
	close(w.quit)
}

// A WorkPool is an abstraction of a set of workers that manages the creation, scheduling, and destruction of workers.
type WorkPool struct {
	minWorkers     int
	maxWorkers     int
	currentWorkers int32
	taskQueue      chan Task
	workers        []*worker
	metrics        *PoolMetrics
	adjustInterval time.Duration
	mu             sync.RWMutex

	workerLoads     []int32
	lastAdjustTime  time.Time
	adjustThreshold float64
}

// PoolMetrics represent the load metrics of the workers in a pool
// and are used for dynamic scaling.These include task load counts,
// average latency, request success rate, CPU and Memory utilization.
type PoolMetrics struct {
	queueUsage     float64
	idleWorkers    float64
	cpuUsage       float64
	memoryUsage    float64
	avgLatency     float64
	successRate    float64
	lastAdjustTime time.Time
}

func NewWorkPool(minWorkers, maxWorkers int, queueSize int) *WorkPool {
	pool := &WorkPool{
		minWorkers:      minWorkers,
		maxWorkers:      maxWorkers,
		currentWorkers:  int32(minWorkers),
		taskQueue:       make(chan Task, queueSize),
		workers:         make([]*worker, 0, maxWorkers),
		metrics:         &PoolMetrics{lastAdjustTime: time.Now()},
		adjustInterval:  time.Second * 5,
		workerLoads:     make([]int32, maxWorkers),
		adjustThreshold: 0.8, // Trigger adjustment at 80% load, also allows user decision making
	}

	// Initially start only the smallest worker thread to avoid wasting resources.
	// Can be expanded through later asynchronous detection
	for i := 0; i < minWorkers; i++ {
		w := newWorker(i)
		pool.workers = append(pool.workers, w)
		w.start()
	}

	// Start the dynamic adjustment co-process
	go pool.adjustWorkers()

	// Start the Task Distribution Concatenation
	go pool.dispatch()

	return pool
}

// dispatch is responsible for distributing tasks
// and dynamically determining the load on the worker to balance after load balancing
// (since the Client has already done something similar by picking the Server
// to send the request through a load balancing policy).
func (p *WorkPool) dispatch() {
	for t := range p.taskQueue {
		workerIndex := p.selectWorker()
		if workerIndex >= 0 {
			p.mu.RLock()
			if workerIndex < len(p.workers) {
				w := p.workers[workerIndex]
				select {
				case w.tasks <- t:
					atomic.AddInt32(&p.workerLoads[workerIndex], 1)
					continue
				default:
					// The worker thread is busy, move on to the next one.
				}
			}
			p.mu.RUnlock()
		}

		// If all workers are busy, use the fallback policy
		p.handleOverload(t)
	}
}

// selectWorker dynamically selects the optimal executing worker
// from the load of the workers recorded in real time.
func (p *WorkPool) selectWorker() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.workers) == 0 {
		return -1
	}

	// Find the least loaded worker thread
	minLoad := int32(math.MaxInt32)
	selectedIndex := -1

	for i, load := range p.workerLoads {
		if i >= len(p.workers) {
			break
		}
		if load < minLoad {
			minLoad = load
			selectedIndex = i
		}
	}

	return selectedIndex
}

// handleOverload handles the state where all workers are busy,
// determines whether to expand the queue based on the current load,
// and if the expansion is successful, uses the expanded worker to handle it,
// otherwise it directly tries to start a new goroutine to execute the task.
func (p *WorkPool) handleOverload(t Task) {
	if p.metrics.queueUsage > p.adjustThreshold {
		p.quickScaleUp()
	}

	p.mu.RLock()
	for i, w := range p.workers {
		select {
		case w.tasks <- t:
			atomic.AddInt32(&p.workerLoads[i], 1)
			p.mu.RUnlock()
			return
		default:
			continue
		}
	}
	p.mu.RUnlock()

	// If still unassigned, deal with it directly
	go t.Run(context.Background())
}

// quickScaleUp is an emergency braking strategy
// that protects the system's security mechanisms
// by turning on a large number of workers at once
// while staying within the maximum tolerable number of workers when unexpected high concurrency traffic hits.
func (p *WorkPool) quickScaleUp() {
	currentWorkers := int(atomic.LoadInt32(&p.currentWorkers))
	if currentWorkers >= p.maxWorkers {
		return
	}

	// Rapidly increase work threads by 20%
	targetWorkers := int(float64(currentWorkers) * 1.2)
	if targetWorkers > p.maxWorkers {
		targetWorkers = p.maxWorkers
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for i := currentWorkers; i < targetWorkers; i++ {
		w := newWorker(i)
		p.workers = append(p.workers, w)
		w.start()
		atomic.AddInt32(&p.currentWorkers, 1)
	}
}

// adjustWorkers asynchronous policy to dynamically monitor and update the status of each worker,
// while fine-tuning the number of workers based on the current load.
func (p *WorkPool) adjustWorkers() {
	ticker := time.NewTicker(p.adjustInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.updateMetrics()
		p.adjustWorkerCount()
	}
}

// updateMetrics Timed task to update worker load metrics for daily fine-tuning.
func (p *WorkPool) updateMetrics() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Update queue utilization
	queueLen := len(p.taskQueue)
	queueCap := cap(p.taskQueue)
	p.metrics.queueUsage = float64(queueLen) / float64(queueCap)

	// Update a worker thread load
	totalLoad := int32(0)
	for i := range p.workerLoads {
		if i < len(p.workers) {
			load := atomic.LoadInt32(&p.workerLoads[i])
			totalLoad += load
		}
	}

	if len(p.workers) > 0 {
		p.metrics.idleWorkers = 1.0 - float64(totalLoad)/float64(len(p.workers))
	}

	// Update system resource utilization
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	p.metrics.cpuUsage = float64(m.Sys) / float64(runtime.NumCPU()*1024*1024)
	p.metrics.memoryUsage = float64(m.Alloc) / float64(m.Sys)
}

// adjustWorkerCount is a daily adjustment strategy, unlike quickScaleUp,
// which only fine-tunes the number of workers based on system runtime timer detection,
// and is not able to cope with highly concurrent traffic, but is a simple strategy to save resources.
func (p *WorkPool) adjustWorkerCount() {
	currentWorkers := int(atomic.LoadInt32(&p.currentWorkers))
	targetWorkers := currentWorkers

	// Adjust the number of worker threads to the load
	if p.metrics.queueUsage > p.adjustThreshold && p.metrics.idleWorkers < 0.2 {
		// High load and few idle threads, increase worker threads
		targetWorkers = int(float64(currentWorkers) * 1.2)
	} else if p.metrics.queueUsage < 0.2 && p.metrics.idleWorkers > 0.8 {
		// Low load and many idle threads, fewer worker threads
		targetWorkers = int(float64(currentWorkers) * 0.8)
	}

	// Ensure that the minimum and maximum ranges
	if targetWorkers < p.minWorkers {
		targetWorkers = p.minWorkers
	} else if targetWorkers > p.maxWorkers {
		targetWorkers = p.maxWorkers
	}

	// If adjustments are needed
	if targetWorkers != currentWorkers {
		p.mu.Lock()
		defer p.mu.Unlock()

		if targetWorkers > currentWorkers {
			// Add worker threads
			for i := currentWorkers; i < targetWorkers; i++ {
				w := newWorker(i)
				p.workers = append(p.workers, w)
				w.start()
				atomic.AddInt32(&p.currentWorkers, 1)
			}
		} else {
			// Reduce work threads
			for i := currentWorkers - 1; i >= targetWorkers; i-- {
				if i < len(p.workers) {
					p.workers[i].stop()
					p.workers = p.workers[:i]
					atomic.AddInt32(&p.currentWorkers, -1)
				}
			}
		}
	}
}

// stop shuts down the work pool
func (p *WorkPool) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, w := range p.workers {
		w.stop()
	}
	close(p.taskQueue)
}
