package natct

import (
	"sync"
	"time"
)

const reassemblyTimeout = 30 * time.Second

type fragGroupKey struct {
	srcIP [4]byte
	dstIP [4]byte
	proto Protocol
	id    uint16
}

type fragPiece struct {
	off  uint16 // 以 8 字节为单位
	data []byte // IP 负载（IP 头之后）
	more bool
	raw  []byte // 原始分片完整字节，用于再分片
	seen time.Time
}

type fragGroup struct {
	pieces   map[uint16]*fragPiece
	lastSeen time.Time
}

// Reassembler 负责 IP 分片的重组与处理后的再分片
type Reassembler struct {
	mu     sync.Mutex
	groups map[fragGroupKey]*fragGroup
	engine *Engine
	now    func() time.Time
}

func NewReassembler(e *Engine) *Reassembler {
	return &Reassembler{
		groups: map[fragGroupKey]*fragGroup{},
		engine: e,
		now:    time.Now,
	}
}

// Process 处理一个入向分片，返回 0 个或多个出向分片（重组完成时产生）。
func (r *Reassembler) Process(raw []byte) ([][]byte, error) {
	p, err := parsePacket(raw)
	if err != nil {
		return nil, err
	}

	key := fragGroupKey{proto: p.Proto, id: p.FragID}
	copy(key.srcIP[:], p.L3[12:16])
	copy(key.dstIP[:], p.L3[16:20])

	// 非分片：直接处理，单片返回
	if !p.MoreFrag && p.FragOff == 0 {
		out, _, err := r.engine.Handle(raw)
		if err != nil {
			return nil, err
		}
		return [][]byte{out}, nil
	}

	r.mu.Lock()
	g, ok := r.groups[key]
	if !ok {
		g = &fragGroup{pieces: map[uint16]*fragPiece{}}
		r.groups[key] = g
	}
	now := r.now()
	g.lastSeen = now

	payload := append([]byte(nil), p.L3[p.ihl:p.tot]...)
	piece := &fragPiece{off: p.FragOff, data: payload, more: p.MoreFrag, raw: raw, seen: now}

	if existing, dup := g.pieces[p.FragOff]; dup {
		if equalBytes(existing.data, payload) {
			// 完全重复分片：忽略，不产生污染
			r.mu.Unlock()
			return nil, nil
		}
		r.mu.Unlock()
		return nil, ErrMalformedPacket
	}
	g.pieces[p.FragOff] = piece

	assembled, order, complete := r.tryAssemble(g)
	if !complete {
		r.mu.Unlock()
		return nil, nil
	}
	delete(r.groups, key)
	r.mu.Unlock()

	out, _, err := r.engine.Handle(assembled)
	if err != nil {
		return nil, err
	}
	return r.refragment(out, order), nil
}

// tryAssemble 在锁内尝试拼装。返回完整数据报与按偏移排序的分片元数据。
func (r *Reassembler) tryAssemble(g *fragGroup) ([]byte, []*fragPiece, bool) {
	first, ok := g.pieces[0]
	if !ok {
		return nil, nil, false
	}
	// 找到最后一片（MF=0）以确定数据报总负载长度
	var last *fragPiece
	for _, pc := range g.pieces {
		if !pc.more {
			if last == nil || pc.off > last.off {
				last = pc
			}
		}
	}
	if last == nil {
		return nil, nil, false
	}
	totalLen := int(last.off)*8 + len(last.data)

	// 按偏移排序并校验连续、无重叠；除末片外每片负载必须 8 字节对齐
	offs := make([]uint16, 0, len(g.pieces))
	for off := range g.pieces {
		offs = append(offs, off)
	}
	sortU16(offs)

	order := make([]*fragPiece, 0, len(g.pieces))
	cursor := 0
	for _, off := range offs {
		pc := g.pieces[off]
		if int(off)*8 != cursor {
			return nil, nil, false
		}
		if pc != last && len(pc.data)%8 != 0 {
			return nil, nil, false
		}
		cursor += len(pc.data)
		order = append(order, pc)
	}
	if cursor != totalLen {
		return nil, nil, false
	}

	// 用首片 IP 头作为基础构造完整数据报
	base := first.raw
	ipHdr := append([]byte(nil), base[:int(base[0]&0x0f)*4]...)
	data := make([]byte, totalLen)
	for _, pc := range order {
		copy(data[int(pc.off)*8:], pc.data)
	}
	dgram := append(ipHdr, data...)
	putBe16(dgram[6:8], 0) // 清除 MF 与片偏移
	putBe16(dgram[2:4], uint16(len(dgram)))
	putBe16(dgram[10:12], 0)
	putBe16(dgram[10:12], ipChecksum(dgram[:int(dgram[0]&0x0f)*4]))
	return dgram, order, true
}

func sortU16(a []uint16) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1] > a[j]; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}

// refragment 按原始分片布局切分改写后的完整数据报
func (r *Reassembler) refragment(dgram []byte, order []*fragPiece) [][]byte {
	ihl := int(dgram[0]&0x0f) * 4
	out := make([][]byte, 0, len(order))
	for _, pc := range order {
		start := int(pc.off) * 8
		end := start + len(pc.data)
		payload := dgram[ihl+start : ihl+end]

		// 以原分片头为基础恢复 MF/片偏移/Id/TTL 等字段，
		// 但地址等改写内容来自处理后的 dgram。
		hdr := append([]byte(nil), pc.raw[:ihl]...)
		copy(hdr[12:16], dgram[12:16]) // 改写后的 src IP
		copy(hdr[16:20], dgram[16:20]) // 改写后的 dst IP
		result := append(hdr, payload...)
		putBe16(result[2:4], uint16(len(result)))
		putBe16(result[10:12], 0)
		putBe16(result[10:12], ipChecksum(result[:ihl]))
		out = append(out, result)
	}
	return out
}

// Reap 清理超时未完成的分片组，返回清理数量
func (r *Reassembler) Reap() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	n := 0
	for k, g := range r.groups {
		if now.Sub(g.lastSeen) >= reassemblyTimeout {
			delete(r.groups, k)
			n++
		}
	}
	return n
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
