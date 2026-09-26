package natct

import "sync"

// PortAllocator 负责映射端口的唯一分配与复用。
// 不同协议拥有各自独立的端口空间；分配顺序为从游标开始环形扫描，
// 因此在相同的操作序列下结果可复现。
type PortAllocator struct {
	mu   sync.Mutex
	min  uint16
	max  uint16
	next map[Protocol]uint16
	busy map[Protocol]map[uint16]struct{}
}

func NewPortAllocator(min, max uint16) *PortAllocator {
	if min == 0 {
		min = 1024
	}
	if max == 0 || max < min {
		max = 65535
	}
	a := &PortAllocator{
		min:  min,
		max:  max,
		next: map[Protocol]uint16{},
		busy: map[Protocol]map[uint16]struct{}{},
	}
	for _, p := range []Protocol{ProtoTCP, ProtoUDP, ProtoICMP} {
		a.next[p] = min
		a.busy[p] = map[uint16]struct{}{}
	}
	return a
}

// Allocate 分配一个未占用端口。preferred 非 0 且空闲时优先使用。
func (a *PortAllocator) Allocate(proto Protocol, preferred uint16) (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	busy, ok := a.busy[proto]
	if !ok {
		busy = map[uint16]struct{}{}
		a.busy[proto] = busy
		a.next[proto] = a.min
	}

	if preferred >= a.min && preferred <= a.max {
		if _, used := busy[preferred]; !used {
			busy[preferred] = struct{}{}
			return preferred, nil
		}
	}

	start := a.next[proto]
	cursor := start
	for {
		if _, used := busy[cursor]; !used {
			busy[cursor] = struct{}{}
			a.next[proto] = a.advance(cursor)
			return cursor, nil
		}
		cursor = a.advance(cursor)
		if cursor == start {
			return 0, ErrNoPortsAvailable
		}
	}
}

func (a *PortAllocator) advance(p uint16) uint16 {
	if p >= a.max {
		return a.min
	}
	return p + 1
}

func (a *PortAllocator) Release(proto Protocol, port uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if busy, ok := a.busy[proto]; ok {
		delete(busy, port)
	}
}

func (a *PortAllocator) InUse(proto Protocol, port uint16) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	busy, ok := a.busy[proto]
	if !ok {
		return false
	}
	_, used := busy[port]
	return used
}

func (a *PortAllocator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, busy := range a.busy {
		n += len(busy)
	}
	return n
}
