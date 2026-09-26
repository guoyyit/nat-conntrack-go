package natct

import (
	"net/netip"
	"sync"
	"time"
)

// State 会话状态
type State uint8

const (
	StateNone State = iota
	StateNew        // TCP: SYN 已发 / UDP,ICMP: 首包已发
	StateEstablished
	StateFinWait
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait:
		return "FIN_WAIT"
	case StateClosed:
		return "CLOSED"
	default:
		return "NONE"
	}
}

// Config 连接跟踪与 NAT 配置
type Config struct {
	PublicIP    netip.Addr
	PortMin     uint16
	PortMax     uint16
	MaxSessions int
	TCPTimeout  time.Duration
	UDPTimeout  time.Duration
	ICMPTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		PortMin:     1024,
		PortMax:     65535,
		MaxSessions: 4096,
		TCPTimeout:  5 * time.Minute,
		UDPTimeout:  30 * time.Second,
		ICMPTimeout: 10 * time.Second,
	}
}

// 半建立与关闭状态使用更短的固定超时
const (
	tcpSynTimeout = 30 * time.Second
	tcpFinTimeout = 10 * time.Second
	closedGrace   = 1 * time.Second
)

// Session 一条双向 NAT 会话
type Session struct {
	ID       uint64
	Original FiveTuple // 去程（改写前）：client -> server
	Reply    FiveTuple // 回程（期望看到的形态）：server -> public
	NatPort  uint16    // 去程分配的映射端口 / ICMP id
	State    State
	Created  time.Time
	LastSeen time.Time
}

func (s *Session) touch(now time.Time) { s.LastSeen = now }

func (s *Session) timeout(cfg Config) time.Duration {
	switch s.Original.Proto {
	case ProtoTCP:
		switch s.State {
		case StateNew:
			return tcpSynTimeout
		case StateFinWait:
			return tcpFinTimeout
		case StateClosed:
			return closedGrace
		default:
			return cfg.TCPTimeout
		}
	case ProtoUDP:
		return cfg.UDPTimeout
	default:
		return cfg.ICMPTimeout
	}
}

func (s *Session) expired(now time.Time, cfg Config) bool {
	return now.Sub(s.LastSeen) >= s.timeout(cfg)
}

// SessionKey 会话查找键
type SessionKey struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	Proto   Protocol
	SrcPort uint16
	DstPort uint16
}

func tupleKey(t FiveTuple) SessionKey {
	return SessionKey{SrcIP: t.SrcIP, DstIP: t.DstIP, Proto: t.Proto, SrcPort: t.SrcPort, DstPort: t.DstPort}
}

type indexEntry struct {
	id  uint64
	dir Direction
}

// Stats 可观测统计（某一时刻的一致快照）
type Stats struct {
	ActiveSessions int
	TotalCreated   uint64
	TotalPackets   uint64
	Rejected       map[string]int
}

// Table 会话表
type Table struct {
	mu       sync.RWMutex
	sessions map[uint64]*Session
	index    map[SessionKey]indexEntry
	nextID   uint64
	config   Config
	ports    *PortAllocator

	totalCreated uint64
	totalPackets uint64
	rejected     map[string]int
}

func NewTable(cfg Config) *Table {
	if cfg.PortMax == 0 {
		cfg = DefaultConfig()
	}
	return &Table{
		sessions: map[uint64]*Session{},
		index:    map[SessionKey]indexEntry{},
		config:   cfg,
		ports:    NewPortAllocator(cfg.PortMin, cfg.PortMax),
		rejected: map[string]int{},
	}
}

// Lookup 按五元组查找会话，返回其方向
func (t *Table) Lookup(k SessionKey) (*Session, Direction) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if e, ok := t.index[k]; ok {
		return t.sessions[e.id], e.dir
	}
	return nil, DirInvalid
}

// Create 为去程首包建立会话；容量满或端口耗尽时整体失败且不留残状态
func (t *Table) Create(tuple FiveTuple, now time.Time) (*Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	k := tupleKey(tuple)
	if _, exists := t.index[k]; exists {
		return t.sessions[t.index[k].id], nil
	}
	if len(t.sessions) >= t.config.MaxSessions {
		t.rejected[errorKey(ErrTableFull)]++
		return nil, ErrTableFull
	}

	// 去程首包统一从 NEW 开始（TCP 已由 Engine 保证为 SYN）
	state := StateNew

	mapped, err := t.ports.Allocate(tuple.Proto, 0)
	if err != nil {
		t.rejected[errorKey(err)]++
		return nil, err
	}

	t.nextID++
	replySrcPort := tuple.DstPort
	replyDstPort := mapped
	if tuple.Proto == ProtoICMP {
		// echo request 的 id 位于 DstPort，映射后回程 id 出现在 SrcPort 位
		replySrcPort = mapped
		replyDstPort = 0
	}
	s := &Session{
		ID:       t.nextID,
		Original: tuple,
		Reply: FiveTuple{
			SrcIP:   tuple.DstIP,
			DstIP:   t.config.PublicIP,
			Proto:   tuple.Proto,
			SrcPort: replySrcPort,
			DstPort: replyDstPort,
		},
		NatPort:  mapped,
		State:    state,
		Created:  now,
		LastSeen: now,
	}
	t.sessions[s.ID] = s
	t.index[k] = indexEntry{id: s.ID, dir: DirOriginal}
	t.index[tupleKey(s.Reply)] = indexEntry{id: s.ID, dir: DirReply}
	t.totalCreated++
	return s, nil
}

// Observe 更新会话状态机；非法转移返回 ErrInvalidState 且不改变状态
func (t *Table) Observe(s *Session, dir Direction, p *Packet, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := s.transition(dir, p); err != nil {
		t.rejected[errorKey(err)]++
		return err
	}
	s.touch(now)
	return nil
}

func (s *Session) transition(dir Direction, p *Packet) error {
	switch p.Proto {
	case ProtoTCP:
		return s.tcpTransition(dir, p.Flags)
	case ProtoUDP:
		if s.State == StateNew && dir == DirReply {
			s.State = StateEstablished
		}
		return nil
	case ProtoICMP:
		if s.State == StateNew && dir == DirReply && p.ICMPType == 0 {
			s.State = StateEstablished
		}
		return nil
	}
	return ErrProtocolUnsupported
}

func (s *Session) tcpTransition(dir Direction, flags uint8) error {
	isSYN := flags&tcpSYN != 0
	isACK := flags&tcpACK != 0
	isFIN := flags&tcpFIN != 0
	isRST := flags&tcpRST != 0

	switch s.State {
	case StateNew:
		switch {
		case isRST:
			s.State = StateClosed
		case dir == DirOriginal && isSYN && !isACK:
			// SYN 重传
		case dir == DirReply && isSYN && isACK:
			// SYN/ACK，等待最后一个 ACK
		case dir == DirOriginal && isACK && !isSYN:
			s.State = StateEstablished
		default:
			return ErrInvalidState
		}
	case StateEstablished:
		switch {
		case isRST:
			s.State = StateClosed
		case isFIN:
			s.State = StateFinWait
		}
	case StateFinWait:
		switch {
		case isRST, isFIN, dir == DirReply && isACK:
			s.State = StateClosed
		}
	case StateClosed:
		if isRST || isSYN {
			return ErrInvalidState
		}
	}
	return nil
}

// ReapExpired 回收超时与已关闭会话，释放映射端口，返回回收数量
func (t *Table) ReapExpired(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for id, s := range t.sessions {
		if !s.expired(now, t.config) {
			continue
		}
		delete(t.index, tupleKey(s.Original))
		delete(t.index, tupleKey(s.Reply))
		t.ports.Release(s.Original.Proto, s.NatPort)
		delete(t.sessions, id)
		n++
	}
	return n
}

// CountPacket 在成功匹配/建连的报文处理路径上计数
func (t *Table) CountPacket() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.totalPackets++
}

// CountReject 记录拒绝原因
func (t *Table) CountReject(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rejected[errorKey(err)]++
}

// Len 返回未关闭会话数
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, s := range t.sessions {
		if s.State != StateClosed {
			n++
		}
	}
	return n
}

// Stats 返回一致快照
func (t *Table) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	rej := make(map[string]int, len(t.rejected))
	for k, v := range t.rejected {
		rej[k] = v
	}
	n := 0
	for _, s := range t.sessions {
		if s.State != StateClosed {
			n++
		}
	}
	return Stats{
		ActiveSessions: n,
		TotalCreated:   t.totalCreated,
		TotalPackets:   t.totalPackets,
		Rejected:       rej,
	}
}

func (t *Table) Close() error { return nil }

func errorKey(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
