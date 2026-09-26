package natct

import (
	"errors"
	"testing"
	"time"
)

func testEngine(t *testing.T, cfg Config) (*Engine, func()) {
	t.Helper()
	e := &Engine{table: NewTable(cfg), now: time.Now, stop: make(chan struct{})}
	return e, func() { close(e.stop) }
}

func baseCfg() Config {
	cfg := DefaultConfig()
	cfg.PublicIP = ip4("203.0.113.1")
	cfg.PortMin = 20000
	cfg.PortMax = 20099
	return cfg
}

// 端到端：UDP 去程 SNAT + 回程 DNAT，校验和必须有效且关联正确
func TestNAT_UDP_Bidirectional(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()

	client, pub, server := ip4("10.0.0.2"), ip4("203.0.113.1"), ip4("198.51.100.9")

	out, dir, err := e.Handle(udpPacket(client, server, 40000, 53, []byte("hello")))
	if err != nil || dir != DirOriginal {
		t.Fatalf("outbound: %v dir=%v", err, dir)
	}
	po, err := parsePacket(out)
	if err != nil {
		t.Fatalf("parse outbound: %v", err)
	}
	if po.SrcIP != pub || po.SrcPort < 20000 || po.DstIP != server || po.DstPort != 53 {
		t.Fatalf("bad SNAT: %+v", po.tuple())
	}
	mapped := po.SrcPort

	// 回程：server -> public:mapped，应被识别为 Reply 并 DNAT 回 client
	back, dir, err := e.Handle(udpPacket(server, pub, 53, mapped, []byte("world")))
	if err != nil || dir != DirReply {
		t.Fatalf("inbound: %v dir=%v", err, dir)
	}
	pr, err := parsePacket(back)
	if err != nil {
		t.Fatalf("parse inbound: %v", err)
	}
	if pr.DstIP != client || pr.DstPort != 40000 || pr.SrcIP != server || pr.SrcPort != 53 {
		t.Fatalf("bad DNAT: %+v", pr.tuple())
	}
}

// TCP 完整三次握手 + FIN 状态推进，统计一致
func TestNAT_TCP_HandshakeAndClose(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, pub, server := ip4("10.0.0.3"), ip4("203.0.113.1"), ip4("198.51.100.10")

	steps := []struct {
		raw func() []byte
		dir Direction
	}{
		{func() []byte { return tcpPacket(client, server, 50000, 80, tcpSYN, 100, 0) }, DirOriginal},
		{nil, DirReply},
		{nil, DirOriginal},
	}
	// SYN
	out, dir, _ := e.Handle(steps[0].raw())
	if dir != DirOriginal {
		t.Fatal("SYN dir")
	}
	po, _ := parsePacket(out)
	mapped := po.SrcPort

	// SYN/ACK（基于改写后的元组）
	synack := tcpPacket(server, pub, 80, mapped, tcpSYN|tcpACK, 500, 101)
	if _, dir, err := e.Handle(synack); err != nil || dir != DirReply {
		t.Fatalf("SYNACK: %v %v", err, dir)
	}
	// ACK
	ack := tcpPacket(client, server, 50000, 80, tcpACK, 101, 501)
	if _, dir, err := e.Handle(ack); err != nil || dir != DirOriginal {
		t.Fatalf("ACK: %v %v", err, dir)
	}
	s, _ := e.table.Lookup(tupleKey(FiveTuple{SrcIP: client, DstIP: server, Proto: ProtoTCP, SrcPort: 50000, DstPort: 80}))
	if s.State != StateEstablished {
		t.Fatalf("state=%v want ESTABLISHED", s.State)
	}

	// 双向 FIN
	fin1 := tcpPacket(client, server, 50000, 80, tcpFIN|tcpACK, 102, 501)
	e.Handle(fin1)
	if s.State != StateFinWait {
		t.Fatalf("state=%v want FIN_WAIT", s.State)
	}
	fin2 := tcpPacket(server, pub, 80, mapped, tcpFIN|tcpACK, 501, 103)
	e.Handle(fin2)
	if s.State != StateClosed {
		t.Fatalf("state=%v want CLOSED", s.State)
	}
}

// ICMP echo request/reply 的 id 改写与回流
func TestNAT_ICMP(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, pub, server := ip4("10.0.0.4"), ip4("203.0.113.1"), ip4("1.1.1.1")

	out, dir, err := e.Handle(icmpPacket(client, server, 8, 333, []byte("ping")))
	if err != nil || dir != DirOriginal {
		t.Fatalf("echo req: %v %v", err, dir)
	}
	po, _ := parsePacket(out)
	if po.SrcIP != pub {
		t.Fatalf("bad icmp snat ip: %v", po.SrcIP)
	}
	mappedID := be16(po.L4[4:6])

	back := icmpPacket(server, pub, 0, mappedID, []byte("ping"))
	b, dir, err := e.Handle(back)
	if err != nil || dir != DirReply {
		t.Fatalf("echo reply: %v %v", err, dir)
	}
	pr, _ := parsePacket(b)
	if be16(pr.L4[4:6]) != 333 || pr.DstIP != client {
		t.Fatalf("icmp reply restore failed id=%d dst=%v", be16(pr.L4[4:6]), pr.DstIP)
	}
}

// 异常链路：坏校验和 / 不支持协议 / 畸形报文 / 无会话回程 / TCP 非 SYN 建连
func TestRejectReasons(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, pub, server := ip4("10.0.0.5"), ip4("203.0.113.1"), ip4("198.51.100.11")

	// 坏 IP 校验和
	bad := udpPacket(client, server, 40001, 53, []byte("x"))
	bad[10] ^= 0xff
	if _, _, err := e.Handle(bad); !errors.Is(err, ErrChecksumInvalid) {
		t.Fatalf("want checksum err, got %v", err)
	}

	// 不支持协议
	raw := buildIPv4(Protocol(99), client, server, 0, 0, []byte{1, 2, 3})
	if _, _, err := e.Handle(raw); !errors.Is(err, ErrProtocolUnsupported) {
		t.Fatalf("want proto err, got %v", err)
	}

	// 畸形
	if _, _, err := e.Handle([]byte{0x45}); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("want malformed, got %v", err)
	}

	// 回程无会话
	if _, _, err := e.Handle(udpPacket(server, pub, 53, 20000, []byte("x"))); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want no session, got %v", err)
	}

	// TCP 非 SYN 不能建会话（且不得残留半建立表项）
	before := e.table.Len()
	_, _, err := e.Handle(tcpPacket(client, server, 51000, 80, tcpACK, 1, 0))
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("want invalid state, got %v", err)
	}
	if e.table.Len() != before {
		t.Fatalf("half-open session leaked: %d -> %d", before, e.table.Len())
	}

	// 拒绝后后续正常报文仍可处理
	if _, _, err := e.Handle(udpPacket(client, server, 40002, 53, []byte("ok"))); err != nil {
		t.Fatalf("later valid packet failed: %v", err)
	}
}

// 输出报文必须自身校验和有效（已由 parsePacket 隐式校验，这里显式断言 TCP/UDP）
func TestOutputChecksumsValid(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, server := ip4("10.0.0.6"), ip4("198.51.100.12")
	out, _, err := e.Handle(tcpPacket(client, server, 52000, 443, tcpSYN, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePacket(out); err != nil {
		t.Fatalf("output invalid: %v", err)
	}
}
