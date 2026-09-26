package natct

import (
	"errors"
	"testing"
	"time"
)

func clockEngine(t *testing.T, cfg Config) (*Engine, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1000, 0)}
	e := &Engine{table: NewTable(cfg), now: clk.now, stop: make(chan struct{})}
	return e, clk
}

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestTimeout_ReapIdleKeepActive(t *testing.T) {
	cfg := baseCfg()
	cfg.UDPTimeout = 30 * time.Second
	e, clk := clockEngine(t, cfg)
	defer close(e.stop)
	client, server := ip4("10.1.0.1"), ip4("198.51.100.20")

	_, _, _ = e.Handle(udpPacket(client, server, 40000, 53, nil))
	if e.table.Len() != 1 {
		t.Fatalf("want 1 session, got %d", e.table.Len())
	}

	// 活跃会话未超时不应被回收
	clk.advance(29 * time.Second)
	if n := e.table.ReapExpired(clk.now()); n != 0 {
		t.Fatalf("active session reaped early: %d", n)
	}

	// 再发报文刷新活跃时间
	clk.advance(10 * time.Second)
	_, _, _ = e.Handle(udpPacket(client, server, 40000, 53, nil))
	clk.advance(20 * time.Second)
	if n := e.table.ReapExpired(clk.now()); n != 0 {
		t.Fatalf("refreshed session should survive: %d", n)
	}

	// 真正空闲超时后被回收，映射端口释放
	clk.advance(11 * time.Second)
	if n := e.table.ReapExpired(clk.now()); n != 1 {
		t.Fatalf("want 1 reaped, got %d", n)
	}
	if e.table.Len() != 0 {
		t.Fatalf("want 0 sessions, got %d", e.table.Len())
	}
	if e.table.ports.Len() != 0 {
		t.Fatalf("ports leaked: %d", e.table.ports.Len())
	}
}

func TestTimeout_TCPSynAndFinShortened(t *testing.T) {
	cfg := baseCfg()
	e, clk := clockEngine(t, cfg)
	defer close(e.stop)
	client, pub, server := ip4("10.1.0.2"), ip4("203.0.113.1"), ip4("198.51.100.21")

	// 仅 SYN，处于 NEW，应使用更短的 tcpSynTimeout（30s），而非 5min
	out, _, _ := e.Handle(tcpPacket(client, server, 50000, 80, tcpSYN, 1, 0))
	po, _ := parsePacket(out)
	mapped := po.SrcPort

	clk.advance(31 * time.Second)
	if n := e.table.ReapExpired(clk.now()); n != 1 {
		t.Fatalf("half-open TCP should reap after 30s, got %d", n)
	}
	// 回收后回程报文应被拒绝为无会话
	_, _, err := e.Handle(tcpPacket(server, pub, 80, mapped, tcpSYN|tcpACK, 1, 1))
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession after reap, got %v", err)
	}
}

func TestCapacity_Limit(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxSessions = 2
	e, clk := clockEngine(t, cfg)
	defer close(e.stop)
	_ = clk

	_, _, err := e.Handle(udpPacket(ip4("10.2.0.1"), ip4("8.8.8.8"), 40001, 53, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = e.Handle(udpPacket(ip4("10.2.0.2"), ip4("8.8.8.8"), 40002, 53, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = e.Handle(udpPacket(ip4("10.2.0.3"), ip4("8.8.8.8"), 40003, 53, nil))
	if !errors.Is(err, ErrTableFull) {
		t.Fatalf("want table full, got %v", err)
	}
	if e.table.Len() != 2 {
		t.Fatalf("want len=2, got %d", e.table.Len())
	}
}

func TestStats_Consistent(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	_, _, _ = e.Handle(udpPacket(ip4("10.3.0.1"), ip4("8.8.8.8"), 40010, 53, nil))
	_, _, _ = e.Handle(udpPacket(ip4("10.3.0.2"), ip4("8.8.8.8"), 40011, 53, nil))
	_, _, badErr := e.Handle([]byte{0x40})
	if badErr == nil {
		t.Fatal("expected reject")
	}
	st := e.table.Stats()
	if st.ActiveSessions != 2 || st.TotalCreated != 2 || st.TotalPackets != 2 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if st.Rejected[errorKey(ErrMalformedPacket)] < 1 {
		t.Fatalf("reject reason missing: %+v", st.Rejected)
	}
}
