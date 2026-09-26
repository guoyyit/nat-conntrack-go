package natct

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestTCP_RSTAndRetransmit(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, pub, server := ip4("10.7.0.1"), ip4("203.0.113.1"), ip4("198.51.100.60")

	// SYN 重传应被接受且不重复建会话
	syn := tcpPacket(client, server, 50000, 80, tcpSYN, 1, 0)
	_, _, _ = e.Handle(syn)
	_, _, _ = e.Handle(syn)
	if e.table.Len() != 1 {
		t.Fatalf("SYN retransmit duplicated session: %d", e.table.Len())
	}
	out, _, _ := e.Handle(syn)
	po, _ := parsePacket(out)

	// 对端 RST：NEW -> CLOSED
	rst := tcpPacket(server, pub, 80, po.SrcPort, tcpRST, 1, 0)
	if _, _, err := e.Handle(rst); err != nil {
		t.Fatal(err)
	}
	s, _ := e.table.Lookup(tupleKey(FiveTuple{SrcIP: client, DstIP: server, Proto: ProtoTCP, SrcPort: 50000, DstPort: 80}))
	if s.State != StateClosed {
		t.Fatalf("want CLOSED, got %v", s.State)
	}
}

func TestTCP_InvalidTransitionRejected(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, pub, server := ip4("10.7.0.2"), ip4("203.0.113.1"), ip4("198.51.100.61")

	e.Handle(tcpPacket(client, server, 50001, 80, tcpSYN, 1, 0))
	// NEW 状态下来自回程的孤立 ACK（无 SYN）是非法转移
	bad := tcpPacket(server, pub, 80, 20000, tcpACK, 1, 0)
	// 用真实映射端口
	s, _ := e.table.Lookup(tupleKey(FiveTuple{SrcIP: client, DstIP: server, Proto: ProtoTCP, SrcPort: 50001, DstPort: 80}))
	bad = tcpPacket(server, pub, 80, s.NatPort, tcpACK, 1, 0)
	_, dir, err := e.Handle(bad)
	if !errors.Is(err, ErrInvalidState) || dir != DirReply {
		t.Fatalf("want invalid state reply, got %v %v", err, dir)
	}
	// 状态不应被污染
	if s.State != StateNew {
		t.Fatalf("state polluted: %v", s.State)
	}
	// 合法握手仍可继续
	if _, _, err := e.Handle(tcpPacket(server, pub, 80, s.NatPort, tcpSYN|tcpACK, 5, 1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Handle(tcpPacket(client, server, 50001, 80, tcpACK, 1, 6)); err != nil {
		t.Fatal(err)
	}
	if s.State != StateEstablished {
		t.Fatalf("want established, got %v", s.State)
	}

	// ESTABLISHED 收到 RST -> CLOSED
	if _, _, err := e.Handle(tcpPacket(server, pub, 80, s.NatPort, tcpRST, 6, 1)); err != nil {
		t.Fatal(err)
	}
	if s.State != StateClosed {
		t.Fatalf("want closed after RST, got %v", s.State)
	}
}

// FIN_WAIT 下回程 ACK 即可关闭，覆盖状态机剩余路径
func TestTCP_FinWaitAckClose(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, pub, server := ip4("10.7.0.3"), ip4("203.0.113.1"), ip4("198.51.100.62")
	establish(t, e, client, server, 50002, 80, pub)
	s, _ := e.table.Lookup(tupleKey(FiveTuple{SrcIP: client, DstIP: server, Proto: ProtoTCP, SrcPort: 50002, DstPort: 80}))

	e.Handle(tcpPacket(client, server, 50002, 80, tcpFIN|tcpACK, 10, 20)) // -> FIN_WAIT
	e.Handle(tcpPacket(server, pub, 80, s.NatPort, tcpACK, 20, 11))       // -> CLOSED
	if s.State != StateClosed {
		t.Fatalf("want closed, got %v", s.State)
	}
}

func establish(t *testing.T, e *Engine, client, server netip.Addr, sport, dport uint16, pub netip.Addr) {
	t.Helper()
	out, _, err := e.Handle(tcpPacket(client, server, sport, dport, tcpSYN, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	po, _ := parsePacket(out)
	if _, _, err := e.Handle(tcpPacket(server, pub, dport, po.SrcPort, tcpSYN|tcpACK, 5, 1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Handle(tcpPacket(client, server, sport, dport, tcpACK, 1, 6)); err != nil {
		t.Fatal(err)
	}
}

// NewEngine 启动后台回收器，超时会话会被自动清理；Close 停止 goroutine
func TestEngine_BackgroundReaperAndClose(t *testing.T) {
	cfg := baseCfg()
	cfg.UDPTimeout = 20 * time.Millisecond
	e := NewEngine(cfg)
	defer e.Close()
	_, _, err := e.Handle(udpPacket(ip4("10.8.0.1"), ip4("8.8.8.8"), 40000, 53, nil))
	if err != nil {
		t.Fatal(err)
	}
	if e.Table().Len() != 1 {
		t.Fatal("session not created")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e.Table().Len() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("background reaper did not reclaim expired session")
}
