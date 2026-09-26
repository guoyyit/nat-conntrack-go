package natct

import (
	"time"
)

// Engine 是 NAT + 连接跟踪的核心处理器
type Engine struct {
	table *Table
	now   func() time.Time
	stop  chan struct{}
}

func NewEngine(cfg Config) *Engine {
	e := &Engine{
		table: NewTable(cfg),
		now:   time.Now,
		stop:  make(chan struct{}),
	}
	go e.reaper(time.Second)
	return e
}

func (e *Engine) reaper(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case now := <-t.C:
			e.table.ReapExpired(now)
		}
	}
}

// Handle 处理单个 IPv4 报文：
//   - 去程（新会话）：SNAT 为 PublicIP + 映射端口
//   - 回程（已存在会话）：DNAT 回原始内网地址与端口
//
// 返回改写后的报文字节与方向；拒绝时 err 给出可区分原因。
func (e *Engine) Handle(raw []byte) ([]byte, Direction, error) {
	p, err := parsePacket(raw)
	if err != nil {
		e.table.CountReject(err)
		return nil, DirInvalid, err
	}
	now := e.now()

	var s *Session
	var dir Direction

	s, dir = e.table.Lookup(p.tuple().sessionKey())
	if s == nil {
		// 非首片在未建立上下文时无法归属，交给分片重组层
		if p.FragOff > 0 {
			err = ErrNoSession
			e.table.CountReject(err)
			return nil, DirInvalid, err
		}
		// 仅去往非 PublicIP 的去程首包允许建会话
		if p.DstIP == e.table.config.PublicIP {
			err = ErrNoSession
			e.table.CountReject(err)
			return nil, DirInvalid, err
		}
		// TCP 必须以 SYN 打开连接，避免创建后立即状态机失败而残留半建立表项
		if p.Proto == ProtoTCP && p.Flags&tcpSYN == 0 {
			err = ErrInvalidState
			e.table.CountReject(err)
			return nil, DirInvalid, err
		}
		s, err = e.table.Create(p.tuple(), now)
		if err != nil {
			// CountReject 已在 Create 内部统计
			return nil, DirInvalid, err
		}
		dir = DirOriginal
	}

	if err := e.table.Observe(s, dir, p, now); err != nil {
		return nil, dir, err
	}

	e.translate(p, s, dir)
	e.table.CountPacket()
	return p.Bytes(), dir, nil
}

func (f FiveTuple) sessionKey() SessionKey {
	return tupleKey(f)
}

// translate 改写地址/端口并保证 IP 与 L4 校验和有效。
// 改写只替换等宽字段，长度不变，故可直接重算校验和。
func (e *Engine) translate(p *Packet, s *Session, dir Direction) {
	switch dir {
	case DirOriginal:
		copy(p.L3[12:16], s.Reply.DstIP.AsSlice()) // src IP -> PublicIP
		if p.Proto == ProtoICMP {
			putBe16(p.L4[4:6], s.NatPort) // echo request id
		} else {
			putBe16(p.L4[0:2], s.NatPort) // src port
		}
	case DirReply:
		copy(p.L3[16:20], s.Original.SrcIP.AsSlice()) // dst IP -> client IP
		if p.Proto == ProtoICMP {
			putBe16(p.L4[4:6], s.Original.DstPort) // echo reply id 还原
		} else {
			putBe16(p.L4[2:4], s.Original.SrcPort) // dst port
		}
	}

	// IP 头校验和
	putBe16(p.L3[10:12], 0)
	putBe16(p.L3[10:12], ipChecksum(p.L3[:p.ihl]))

	// 传输层校验和
	switch p.Proto {
	case ProtoICMP:
		putBe16(p.L4[2:4], 0)
		putBe16(p.L4[2:4], csumFold(csum(p.L4)))
	case ProtoUDP:
		putBe16(p.L4[6:8], 0)
		sum := computeL4Checksum(p, p.L4)
		// UDP 校验和 0 有“不校验”语义，计算结果为 0 时需写成 0xffff
		if sum == 0 {
			sum = 0xffff
		}
		putBe16(p.L4[6:8], sum)
	default: // TCP
		putBe16(p.L4[16:18], 0)
		putBe16(p.L4[16:18], computeL4Checksum(p, p.L4))
	}
}

func (e *Engine) Table() *Table { return e.table }
func (e *Engine) Close() error {
	close(e.stop)
	return e.table.Close()
}
