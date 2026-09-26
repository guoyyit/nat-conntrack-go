// Package conntrack 提供基于五元组的连接跟踪能力。
//
// 状态机：
//
//	New -> Established -> Closing -> Closed
//
// TCP 由标志位驱动迁移（SYN 建连、ACK 确立、FIN 关闭、RST 终止）；
// UDP/ICMP 在去程首包进入 New，见到回程包后进入 Established。
// 重复与乱序报文的迁移是幂等的，不会污染状态。
package conntrack

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

// 连接跟踪层的可区分错误。
var (
	ErrTableFull         = errors.New("conntrack: table full")
	ErrInvalidTransition = errors.New("conntrack: invalid state transition")
)

// Protocol 与 packet 包保持一致的协议号定义（避免循环依赖，此处独立定义）。
type Protocol uint8

const (
	ProtocolICMP Protocol = 1
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
)

// TCP 标志位（与 packet 包一致）。
const (
	tcpFIN uint8 = 0x01
	tcpSYN uint8 = 0x02
	tcpRST uint8 = 0x04
	tcpACK uint8 = 0x10
)

// 各状态的默认超时。
const (
	DefaultTCPTimeout         = 2 * time.Hour
	DefaultUDPTimeout         = 3 * time.Minute
	DefaultICMPTimeout        = 30 * time.Second
	defaultClosingTimeout     = 30 * time.Second
	defaultClosedTimeout      = 10 * time.Second
	defaultUnconfirmedTimeout = 30 * time.Second
)

// Tuple 表示单向流的五元组标识。
type Tuple struct {
	Protocol Protocol
	SrcAddr  netip.Addr
	DstAddr  netip.Addr
	SrcPort  uint16
	DstPort  uint16
}

// State 表示会话状态机中的状态。
type State int

const (
	StateNew State = iota
	StateEstablished
	StateClosing
	StateClosed
)

// String 返回状态的可读名称。
func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateEstablished:
		return "ESTABLISHED"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Entry 表示一条连接跟踪表项，包含去程与回程两个方向。
type Entry struct {
	Orig     Tuple
	Reply    Tuple
	State    State
	Created  time.Time
	LastSeen time.Time
	Timeout  time.Duration
	Packets  uint64
	Bytes    uint64
}

// Expired 报告表项在 now 时刻是否已超时。
func (e *Entry) Expired(now time.Time) bool {
	return now.Sub(e.LastSeen) >= e.Timeout
}

// Stats 为表统计信息的快照。
type Stats struct {
	Entries  int
	Capacity int
	Created  uint64
	Expired  uint64
	Evicted  uint64
	Dropped  uint64
}

// Table 为连接跟踪表，支持并发读写。
// 容量满时的策略：先回收已超时表项，再淘汰最久未活跃（LRU）表项。
type Table struct {
	mu      sync.RWMutex
	cap     int
	byOrig  map[Tuple]*Entry
	byReply map[Tuple]*Entry

	created uint64
	expired uint64
	evicted uint64
	dropped uint64
}

// NewTable 创建容量为 capacity 的连接跟踪表。
func NewTable(capacity int) *Table {
	if capacity <= 0 {
		capacity = 1
	}
	return &Table{
		cap:     capacity,
		byOrig:  make(map[Tuple]*Entry),
		byReply: make(map[Tuple]*Entry),
	}
}

// lookup 按五元组查找表项（调用方须持锁）。
func (t *Table) lookup(tuple Tuple) (*Entry, bool) {
	if e, ok := t.byOrig[tuple]; ok {
		return e, true
	}
	if e, ok := t.byReply[tuple]; ok {
		return e, true
	}
	return nil, false
}

// Get 按五元组查找表项（正向或反向均可命中）。
func (t *Table) Get(tuple Tuple) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lookup(tuple)
}

// Create 新建一条双向表项；容量不足时先回收超时项、再淘汰 LRU 项。
func (t *Table) Create(orig, reply Tuple, timeout time.Duration) (*Entry, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if e, ok := t.lookup(orig); ok {
		// 重复创建（如重传的 SYN）：直接返回既有表项，保证幂等。
		return e, nil
	}
	if timeout <= 0 {
		timeout = defaultUnconfirmedTimeout
	}
	if len(t.byOrig) >= t.cap {
		t.reapLocked(time.Now())
	}
	if len(t.byOrig) >= t.cap {
		t.evictLRULocked()
	}
	if len(t.byOrig) >= t.cap {
		t.dropped++
		return nil, ErrTableFull
	}
	now := time.Now()
	e := &Entry{
		Orig:     orig,
		Reply:    reply,
		State:    StateNew,
		Created:  now,
		LastSeen: now,
		Timeout:  timeout,
	}
	t.byOrig[orig] = e
	t.byReply[reply] = e
	t.created++
	return e, nil
}

// Update 用到达的报文更新表项状态与活动时间。
// tuple 为报文的五元组（正向或反向），tcpFlags 对非 TCP 传 0，n 为报文字节数。
// 命中已关闭表项等非法迁移时返回 ErrInvalidTransition，且不修改任何状态。
func (t *Table) Update(tuple Tuple, tcpFlags uint8, n int, now time.Time) (*Entry, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.lookup(tuple)
	if !ok {
		return nil, nil
	}
	if e.State == StateClosed {
		return nil, ErrInvalidTransition
	}

	forward := tuple == e.Orig
	next := e.State
	switch e.State {
	case StateNew:
		if e.Orig.Protocol == ProtocolTCP {
			switch {
			case forward && tcpFlags&tcpSYN != 0 && tcpFlags&tcpACK == 0:
				// 首 SYN（含重传）：保持 New。
			case !forward && tcpFlags&tcpSYN != 0 && tcpFlags&tcpACK != 0:
				next = StateEstablished // SYN-ACK
			case tcpFlags&tcpRST != 0:
				next = StateClosed
			case tcpFlags&tcpACK != 0:
				next = StateEstablished // 乱序的 ACK，宽容处理
			}
		} else {
			if !forward {
				next = StateEstablished // UDP/ICMP 见到回程包
			}
		}
	case StateEstablished:
		if e.Orig.Protocol == ProtocolTCP {
			switch {
			case tcpFlags&tcpRST != 0:
				next = StateClosed
			case tcpFlags&tcpFIN != 0:
				next = StateClosing
			}
		}
	case StateClosing:
		if e.Orig.Protocol == ProtocolTCP {
			switch {
			case tcpFlags&tcpRST != 0:
				next = StateClosed
			case tcpFlags&tcpFIN != 0:
				next = StateClosed // 对端 FIN，双向关闭
			}
		}
	}

	if next != e.State {
		e.State = next
		switch next {
		case StateEstablished:
			if e.Orig.Protocol == ProtocolTCP {
				e.Timeout = DefaultTCPTimeout
			}
		case StateClosing:
			e.Timeout = defaultClosingTimeout
		case StateClosed:
			e.Timeout = defaultClosedTimeout
		}
	}
	e.LastSeen = now
	e.Packets++
	e.Bytes += uint64(n)
	return e, nil
}

// Delete 删除指定五元组对应的表项。
func (t *Table) Delete(tuple Tuple) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.lookup(tuple); ok {
		t.removeLocked(e)
	}
}

// removeLocked 从两个索引中移除表项（调用方须持锁）。
func (t *Table) removeLocked(e *Entry) {
	delete(t.byOrig, e.Orig)
	delete(t.byReply, e.Reply)
}

// Reap 回收所有已超时的表项，返回回收数量。
func (t *Table) Reap(now time.Time) int {
	return t.ReapFunc(now, nil)
}

// ReapFunc 回收所有已超时的表项，并对每条被回收的表项调用 fn
// （fn 在锁外调用，可安全执行端口释放等操作）。
func (t *Table) ReapFunc(now time.Time, fn func(*Entry)) int {
	t.mu.Lock()
	var removed []*Entry
	for _, e := range t.byOrig {
		if e.Expired(now) {
			t.removeLocked(e)
			t.expired++
			removed = append(removed, e)
		}
	}
	t.mu.Unlock()
	if fn != nil {
		for _, e := range removed {
			fn(e)
		}
	}
	return len(removed)
}

// Reset 清空全部表项并返回被移除的表项列表，用于资源回收。
func (t *Table) Reset() []*Entry {
	t.mu.Lock()
	removed := make([]*Entry, 0, len(t.byOrig))
	for _, e := range t.byOrig {
		removed = append(removed, e)
	}
	t.byOrig = make(map[Tuple]*Entry)
	t.byReply = make(map[Tuple]*Entry)
	t.mu.Unlock()
	return removed
}

func (t *Table) reapLocked(now time.Time) int {
	n := 0
	for _, e := range t.byOrig {
		if e.Expired(now) {
			t.removeLocked(e)
			t.expired++
			n++
		}
	}
	return n
}

// evictLRULocked 淘汰最久未活跃的表项（调用方须持锁）。
func (t *Table) evictLRULocked() {
	var oldest *Entry
	for _, e := range t.byOrig {
		if oldest == nil || e.LastSeen.Before(oldest.LastSeen) {
			oldest = e
		}
	}
	if oldest != nil {
		t.removeLocked(oldest)
		t.evicted++
	}
}

// Len 返回当前表项数量。
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byOrig)
}

// Stats 返回统计信息快照。
func (t *Table) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Stats{
		Entries:  len(t.byOrig),
		Capacity: t.cap,
		Created:  t.created,
		Expired:  t.expired,
		Evicted:  t.evicted,
		Dropped:  t.dropped,
	}
}
