// Package pipe 提供本地内存管道，模拟报文的输入与输出。
package pipe

import "sync"

// Pipe 为单向内存报文管道，可并发读写。
type Pipe struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	cap    int
	closed bool
}

// New 创建容量为 capacity 的管道。
func New(capacity int) *Pipe {
	if capacity <= 0 {
		capacity = 1
	}
	p := &Pipe{cap: capacity}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Send 向管道写入一个报文；管道满或已关闭时返回 false。
// 报文会被拷贝，调用方可复用缓冲区。
func (p *Pipe) Send(data []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.queue) >= p.cap {
		return false
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	p.queue = append(p.queue, buf)
	p.cond.Signal()
	return true
}

// Recv 从管道读取一个报文；管道空时返回 nil, false。
func (p *Pipe) Recv() ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.queue) == 0 {
		return nil, false
	}
	data := p.queue[0]
	p.queue[0] = nil
	p.queue = p.queue[1:]
	return data, true
}

// Len 返回管道内当前报文数。
func (p *Pipe) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queue)
}

// Close 关闭管道并丢弃残留报文，保证不残留半建立状态。
func (p *Pipe) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.queue = nil
	p.cond.Broadcast()
}
