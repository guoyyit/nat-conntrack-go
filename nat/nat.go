// Package nat 在连接跟踪之上提供地址与端口改写能力。
//
// 出站方向（DirOutbound）做源地址/源端口改写（SNAT）；
// 入站方向（DirInbound）依据同一条会话做目的地址/目的端口反向改写，
// 保证双向流量正确回流。分片报文通过首片建立的分片缓存关联到同一会话。
package nat

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guoyyit/nat-conntrack-go/conntrack"
	"github.com/guoyyit/nat-conntrack-go/packet"
)

// 可区分的拒绝原因。
var (
	ErrChecksumInvalid     = errors.New("nat: packet checksum invalid")
	ErrProtocolUnsupported = errors.New("nat: protocol unsupported")
	ErrTableFull           = errors.New("nat: conntrack table full")
	ErrNoPortAvailable     = errors.New("nat: no port available")
	ErrPortInUse           = errors.New("nat: port already in use")
	ErrInvalidState        = errors.New("nat: invalid state transition")
	ErrMalformedPacket     = errors.New("nat: malformed packet")
	ErrNoSession           = errors.New("nat: no matching session")
)

// Direction 表示报文方向。
type Direction int

const (
	DirOutbound Direction = iota // 内网 -> 外网（做 SNAT）
	DirInbound                   // 外网 -> 内网（做反向改写）
)

// Config 为 NAT 引擎配置。
type Config struct {
	ExternalAddr netip.Addr // 出口公网地址
	PortRangeMin uint16
	PortRangeMax uint16
	TableSize    int
}

// fragKey 标识一个分片数据报（以到达时的地址视图为准）。
type fragKey struct {
	src   netip.Addr
	dst   netip.Addr
	proto uint8
	id    uint16
}

type fragEntry struct {
	tuple   conntrack.Tuple
	expires time.Time
}

// fragCacheTTL 为分片缓存的存活时间。
const fragCacheTTL = 30 * time.Second

// Engine 为 NAT 引擎，组合端口分配器与连接跟踪表。
type Engine struct {
	cfg   Config
	table *conntrack.Table
	ports *PortAllocator

	fragMu sync.Mutex
	frags  map[fragKey]fragEntry

	packetsIn  atomic.Uint64
	packetsOut atomic.Uint64
	rejected   atomic.Uint64
}

// NewEngine 创建 NAT 引擎。
func NewEngine(cfg Config) (*Engine, error) {
	if !cfg.ExternalAddr.Is4() {
		return nil, fmt.Errorf("%w: external address must be IPv4", ErrMalformedPacket)
	}
	if cfg.TableSize <= 0 {
		cfg.TableSize = 4096
	}
	if cfg.PortRangeMin == 0 && cfg.PortRangeMax == 0 {
		cfg.PortRangeMin, cfg.PortRangeMax = 10000, 60999
	}
	return &Engine{
		cfg:   cfg,
		table: conntrack.NewTable(cfg.TableSize),
		ports: NewPortAllocator(cfg.PortRangeMin, cfg.PortRangeMax),
		frags: make(map[fragKey]fragEntry),
	}, nil
}

// tupleFrom 由报文构造五元组。
func tupleFrom(pkt *packet.Packet) conntrack.Tuple {
	return conntrack.Tuple{
		Protocol: conntrack.Protocol(pkt.Protocol),
		SrcAddr:  pkt.SrcAddr,
		DstAddr:  pkt.DstAddr,
		SrcPort:  pkt.SrcPort,
		DstPort:  pkt.DstPort,
	}
}

// Process 处理一个报文：解析、查表/建表、改写地址端口并修正校验和。
// 返回改写后的报文字节；拒绝时返回可区分的错误（可用 errors.Is 判定）。
func (e *Engine) Process(data []byte, dir Direction) ([]byte, error) {
	e.packetsIn.Add(1)

	pkt, err := packet.Parse(data)
	if err != nil {
		e.rejected.Add(1)
		if errors.Is(err, packet.ErrChecksumInvalid) {
			return nil, ErrChecksumInvalid
		}
		return nil, fmt.Errorf("%w: %v", ErrMalformedPacket, err)
	}

	switch pkt.Protocol {
	case packet.ProtocolTCP, packet.ProtocolUDP:
	case packet.ProtocolICMP:
		// 仅支持 echo 请求/应答的地址改写，其余 ICMP 类型不支持。
		if pkt.IsFirstFragment() && pkt.ICMPType != 0 && pkt.ICMPType != 8 {
			e.rejected.Add(1)
			return nil, fmt.Errorf("%w: icmp type %d", ErrProtocolUnsupported, pkt.ICMPType)
		}
	default:
		e.rejected.Add(1)
		return nil, fmt.Errorf("%w: %s", ErrProtocolUnsupported, pkt.Protocol)
	}

	// 确定报文对应的会话五元组；非首片通过分片缓存关联。
	var tuple conntrack.Tuple
	if pkt.IsFirstFragment() {
		tuple = tupleFrom(pkt)
	} else {
		t, ok := e.fragLookup(pkt)
		if !ok {
			e.rejected.Add(1)
			return nil, ErrNoSession
		}
		tuple = t
	}

	// 更新既有会话状态；非法迁移（如已关闭会话上的报文）会被拒绝。
	entry, err := e.table.Update(tuple, pkt.TCPFlags, len(data), time.Now())
	if err != nil {
		e.rejected.Add(1)
		return nil, ErrInvalidState
	}
	if entry == nil {
		if dir != DirOutbound {
			// 入站报文必须命中既有会话，否则丢弃。
			e.rejected.Add(1)
			return nil, ErrNoSession
		}
		entry, err = e.createSession(tuple)
		if err != nil {
			e.rejected.Add(1)
			return nil, err
		}
		// 新建会话也计入本次报文。
		if _, err := e.table.Update(tuple, pkt.TCPFlags, len(data), time.Now()); err != nil {
			e.rejected.Add(1)
			return nil, ErrInvalidState
		}
	}

	// 首片建立分片缓存，供后续分片关联同一会话。
	if pkt.IsFragment() && pkt.IsFirstFragment() {
		e.fragStore(pkt, tuple)
	}

	// 地址与端口改写。
	if dir == DirOutbound {
		pkt.SrcAddr = e.cfg.ExternalAddr
		pkt.SrcPort = entry.Reply.DstPort
		if pkt.Protocol == packet.ProtocolICMP {
			pkt.DstPort = pkt.SrcPort // identifier 同步
		}
	} else {
		pkt.DstAddr = entry.Orig.SrcAddr
		pkt.DstPort = entry.Orig.SrcPort
		if pkt.Protocol == packet.ProtocolICMP {
			pkt.SrcPort = pkt.DstPort // identifier 同步
		}
	}

	out, err := pkt.Serialize()
	if err != nil {
		e.rejected.Add(1)
		return nil, fmt.Errorf("%w: %v", ErrMalformedPacket, err)
	}
	e.packetsOut.Add(1)
	return out, nil
}

// createSession 为新的出站流创建会话：分配映射端口并建立双向表项。
func (e *Engine) createSession(tuple conntrack.Tuple) (*conntrack.Entry, error) {
	mapped, err := e.ports.Alloc(tuple.SrcPort)
	if err != nil {
		return nil, err
	}
	reply := conntrack.Tuple{
		Protocol: tuple.Protocol,
		SrcAddr:  tuple.DstAddr,
		DstAddr:  e.cfg.ExternalAddr,
		SrcPort:  tuple.DstPort,
		DstPort:  mapped,
	}
	if tuple.Protocol == conntrack.ProtocolICMP {
		// ICMP echo 的 identifier 是单一字段，回程两个“端口”均为映射值。
		reply.SrcPort = mapped
	}
	timeout := conntrack.DefaultTCPTimeout
	switch tuple.Protocol {
	case conntrack.ProtocolUDP:
		timeout = conntrack.DefaultUDPTimeout
	case conntrack.ProtocolICMP:
		timeout = conntrack.DefaultICMPTimeout
	}
	entry, err := e.table.Create(tuple, reply, timeout)
	if err != nil {
		e.ports.Release(mapped)
		if errors.Is(err, conntrack.ErrTableFull) {
			return nil, ErrTableFull
		}
		return nil, err
	}
	if entry.Reply.DstPort != mapped {
		// 并发下同一五元组已被建表：释放多分配的端口，复用既有会话。
		e.ports.Release(mapped)
	}
	return entry, nil
}

// fragStore 记录首片的分片缓存（键使用到达时的地址视图）。
func (e *Engine) fragStore(pkt *packet.Packet, tuple conntrack.Tuple) {
	k := fragKey{src: pkt.SrcAddr, dst: pkt.DstAddr, proto: uint8(pkt.Protocol), id: pkt.ID}
	e.fragMu.Lock()
	e.frags[k] = fragEntry{tuple: tuple, expires: time.Now().Add(fragCacheTTL)}
	e.fragMu.Unlock()
}

// fragLookup 查找非首片对应的会话五元组。
func (e *Engine) fragLookup(pkt *packet.Packet) (conntrack.Tuple, bool) {
	k := fragKey{src: pkt.SrcAddr, dst: pkt.DstAddr, proto: uint8(pkt.Protocol), id: pkt.ID}
	e.fragMu.Lock()
	defer e.fragMu.Unlock()
	fe, ok := e.frags[k]
	if !ok || time.Now().After(fe.expires) {
		delete(e.frags, k)
		return conntrack.Tuple{}, false
	}
	return fe.tuple, true
}

// Reap 回收超时会话并释放其映射端口，返回回收数量。
func (e *Engine) Reap() int {
	now := time.Now()
	n := e.table.ReapFunc(now, func(entry *conntrack.Entry) {
		e.ports.Release(entry.Reply.DstPort)
	})
	e.fragMu.Lock()
	for k, fe := range e.frags {
		if now.After(fe.expires) {
			delete(e.frags, k)
		}
	}
	e.fragMu.Unlock()
	return n
}

// Stats 返回引擎统计快照。
func (e *Engine) Stats() Stats {
	return Stats{
		Conntrack:   e.table.Stats(),
		ActivePorts: e.ports.Count(),
		PacketsIn:   e.packetsIn.Load(),
		PacketsOut:  e.packetsOut.Load(),
		Rejected:    e.rejected.Load(),
	}
}

// Stats 为引擎统计信息。
type Stats struct {
	Conntrack   conntrack.Stats
	ActivePorts int
	PacketsIn   uint64
	PacketsOut  uint64
	Rejected    uint64
}

// Close 释放引擎资源：清空会话表并释放全部映射端口，
// 保证异常或重启后不残留半建立状态影响后续会话。
func (e *Engine) Close() {
	for _, entry := range e.table.Reset() {
		e.ports.Release(entry.Reply.DstPort)
	}
	e.fragMu.Lock()
	e.frags = make(map[fragKey]fragEntry)
	e.fragMu.Unlock()
}
