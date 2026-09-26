package nat

import "sync"

// PortAllocator 负责在指定范围内分配唯一端口，支持复用与冲突检测。
// 分配策略是确定性的：优先使用 prefer，否则取范围内最小的空闲端口，
// 因而相同操作序列下结果可复现。所有方法均可并发调用。
type PortAllocator struct {
	mu   sync.Mutex
	min  uint16
	max  uint16
	used map[uint16]struct{}
}

// NewPortAllocator 创建端口分配器，范围为 [min, max]。
func NewPortAllocator(min, max uint16) *PortAllocator {
	if min > max {
		min, max = max, min
	}
	return &PortAllocator{min: min, max: max, used: make(map[uint16]struct{})}
}

// Alloc 分配一个空闲端口；prefer 落在范围内且空闲时优先使用。
func (a *PortAllocator) Alloc(prefer uint16) (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prefer >= a.min && prefer <= a.max {
		if _, ok := a.used[prefer]; !ok {
			a.used[prefer] = struct{}{}
			return prefer, nil
		}
	}
	for p := a.min; ; p++ {
		if _, ok := a.used[p]; !ok {
			a.used[p] = struct{}{}
			return p, nil
		}
		if p == a.max {
			break
		}
	}
	return 0, ErrNoPortAvailable
}

// Reserve 尝试占用指定端口，已被占用或超出范围时返回错误。
func (a *PortAllocator) Reserve(port uint16) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if port < a.min || port > a.max {
		return ErrNoPortAvailable
	}
	if _, ok := a.used[port]; ok {
		return ErrPortInUse
	}
	a.used[port] = struct{}{}
	return nil
}

// Release 释放端口，使其可被再次分配；重复释放是安全的。
func (a *PortAllocator) Release(port uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, port)
}

// InUse 报告端口当前是否被占用。
func (a *PortAllocator) InUse(port uint16) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.used[port]
	return ok
}

// Count 返回当前已分配端口数。
func (a *PortAllocator) Count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}
