package nat_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/guoyyit/nat-conntrack-go/internal/testutil"
	"github.com/guoyyit/nat-conntrack-go/nat"
	"github.com/guoyyit/nat-conntrack-go/packet"
)

var (
	lanHost = testutil.Addr("10.0.0.1")
	wanHost = testutil.Addr("8.8.8.8")
	extAddr = testutil.Addr("203.0.113.1")
)

func newEngine(t *testing.T) *nat.Engine {
	t.Helper()
	e, err := nat.NewEngine(nat.Config{
		ExternalAddr: extAddr,
		PortRangeMin: 40000,
		PortRangeMax: 40100,
		TableSize:    256,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(e.Close)
	return e
}

func TestBidirectionalTCP(t *testing.T) {
	e := newEngine(t)
	// 去程 SYN
	syn := testutil.BuildTCP(lanHost, wanHost, 12345, 80, packet.TCPSYN, nil)
	out, err := e.Process(syn, nat.DirOutbound)
	if err != nil {
		t.Fatalf("outbound SYN: %v", err)
	}
	p, _ := packet.Parse(out)
	if p.SrcAddr != extAddr || p.SrcPort == 12345 {
		t.Fatalf("SNAT not applied: src=%v:%d", p.SrcAddr, p.SrcPort)
	}
	mapped := p.SrcPort

	// 回程 SYN-ACK 应正确反向改写
	synack := testutil.BuildTCP(wanHost, extAddr, 80, mapped, packet.TCPSYN|packet.TCPACK, nil)
	in, err := e.Process(synack, nat.DirInbound)
	if err != nil {
		t.Fatalf("inbound SYN-ACK: %v", err)
	}
	q, _ := packet.Parse(in)
	if q.DstAddr != lanHost || q.DstPort != 12345 {
		t.Fatalf("reverse NAT not applied: dst=%v:%d", q.DstAddr, q.DstPort)
	}
	// 会话应已确立
	if st := e.Stats(); st.Conntrack.Entries != 1 {
		t.Fatalf("entries = %d, want 1", st.Conntrack.Entries)
	}
}

func TestBidirectionalUDP(t *testing.T) {
	e := newEngine(t)
	req := testutil.BuildUDP(lanHost, wanHost, 5353, 53, []byte("q"))
	out, err := e.Process(req, nat.DirOutbound)
	if err != nil {
		t.Fatalf("outbound UDP: %v", err)
	}
	p, _ := packet.Parse(out)
	resp := testutil.BuildUDP(wanHost, extAddr, 53, p.SrcPort, []byte("a"))
	in, err := e.Process(resp, nat.DirInbound)
	if err != nil {
		t.Fatalf("inbound UDP: %v", err)
	}
	q, _ := packet.Parse(in)
	if q.DstAddr != lanHost || q.DstPort != 5353 {
		t.Fatalf("reverse NAT: dst=%v:%d", q.DstAddr, q.DstPort)
	}
}

func TestICMPEcho(t *testing.T) {
	e := newEngine(t)
	ping := testutil.BuildICMPEcho(lanHost, wanHost, 777, false, []byte("x"))
	out, err := e.Process(ping, nat.DirOutbound)
	if err != nil {
		t.Fatalf("outbound ICMP: %v", err)
	}
	p, _ := packet.Parse(out)
	pong := testutil.BuildICMPEcho(wanHost, extAddr, p.SrcPort, true, []byte("x"))
	if _, err := e.Process(pong, nat.DirInbound); err != nil {
		t.Fatalf("inbound ICMP: %v", err)
	}
}

func TestFragmentedPacket(t *testing.T) {
	e := newEngine(t)
	udp := testutil.BuildUDP(lanHost, wanHost, 5000, 53, make([]byte, 64))
	frags := testutil.Fragment(udp, 24)
	if len(frags) < 3 {
		t.Fatalf("want >=3 fragments, got %d", len(frags))
	}
	var mapped uint16
	for i, f := range frags {
		out, err := e.Process(f, nat.DirOutbound)
		if err != nil {
			t.Fatalf("fragment %d: %v", i, err)
		}
		p, err := packet.Parse(out)
		if err != nil {
			t.Fatalf("fragment %d re-parse: %v", i, err)
		}
		if p.SrcAddr != extAddr {
			t.Fatalf("fragment %d src not rewritten: %v", i, p.SrcAddr)
		}
		if i == 0 {
			mapped = p.SrcPort
		}
	}
	// 回程分片也应归入同一会话。
	resp := testutil.BuildUDP(wanHost, extAddr, 53, mapped, make([]byte, 64))
	rfrags := testutil.Fragment(resp, 24)
	for i, f := range rfrags {
		out, err := e.Process(f, nat.DirInbound)
		if err != nil {
			t.Fatalf("reply fragment %d: %v", i, err)
		}
		p, _ := packet.Parse(out)
		if p.DstAddr != lanHost {
			t.Fatalf("reply fragment %d dst not rewritten: %v", i, p.DstAddr)
		}
	}
	// 全部分片归入同一条会话，不产生额外表项。
	if n := e.Stats().Conntrack.Entries; n != 1 {
		t.Fatalf("entries = %d, want 1", n)
	}
}

func TestOutOfOrderFragments(t *testing.T) {
	e := newEngine(t)
	udp := testutil.BuildUDP(lanHost, wanHost, 5001, 53, make([]byte, 64))
	frags := testutil.Fragment(udp, 24)
	// 首片先到，后续分片乱序到达。
	if _, err := e.Process(frags[0], nat.DirOutbound); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	for i := len(frags) - 1; i >= 1; i-- {
		if _, err := e.Process(frags[i], nat.DirOutbound); err != nil {
			t.Fatalf("fragment %d: %v", i, err)
		}
	}
	if n := e.Stats().Conntrack.Entries; n != 1 {
		t.Fatalf("entries = %d, want 1", n)
	}
}

func TestDuplicatePacket(t *testing.T) {
	e := newEngine(t)
	syn := testutil.BuildTCP(lanHost, wanHost, 12345, 80, packet.TCPSYN, nil)
	if _, err := e.Process(syn, nat.DirOutbound); err != nil {
		t.Fatalf("first SYN: %v", err)
	}
	// 重传的 SYN 必须归入同一会话，不新建表项。
	if _, err := e.Process(syn, nat.DirOutbound); err != nil {
		t.Fatalf("dup SYN: %v", err)
	}
	st := e.Stats()
	if st.Conntrack.Entries != 1 || st.Conntrack.Created != 1 {
		t.Fatalf("stats: %+v", st.Conntrack)
	}
}

func TestMalformedPacketRejected(t *testing.T) {
	e := newEngine(t)
	if _, err := e.Process([]byte{0x45, 0x00}, nat.DirOutbound); !errors.Is(err, nat.ErrMalformedPacket) {
		t.Fatalf("err = %v, want ErrMalformedPacket", err)
	}
	bad := testutil.BuildTCP(lanHost, wanHost, 1, 80, packet.TCPSYN, nil)
	bad[10] ^= 0xff
	if _, err := e.Process(bad, nat.DirOutbound); !errors.Is(err, nat.ErrChecksumInvalid) {
		t.Fatalf("err = %v, want ErrChecksumInvalid", err)
	}
	// 异常报文不应影响后续正常报文。
	syn := testutil.BuildTCP(lanHost, wanHost, 12345, 80, packet.TCPSYN, nil)
	if _, err := e.Process(syn, nat.DirOutbound); err != nil {
		t.Fatalf("subsequent packet: %v", err)
	}
}

func TestUnsupportedProtocolRejected(t *testing.T) {
	e := newEngine(t)
	gre := testutil.BuildIPv4(lanHost, wanHost, 47, 1, []byte("gre"))
	if _, err := e.Process(gre, nat.DirOutbound); !errors.Is(err, nat.ErrProtocolUnsupported) {
		t.Fatalf("err = %v, want ErrProtocolUnsupported", err)
	}
}

func TestInboundWithoutSessionDropped(t *testing.T) {
	e := newEngine(t)
	pkt := testutil.BuildTCP(wanHost, extAddr, 80, 40000, packet.TCPACK, nil)
	if _, err := e.Process(pkt, nat.DirInbound); !errors.Is(err, nat.ErrNoSession) {
		t.Fatalf("err = %v, want ErrNoSession", err)
	}
}

func TestInvalidStateTransition(t *testing.T) {
	e := newEngine(t)
	syn := testutil.BuildTCP(lanHost, wanHost, 12345, 80, packet.TCPSYN, nil)
	out, _ := e.Process(syn, nat.DirOutbound)
	p, _ := packet.Parse(out)
	mapped := p.SrcPort
	// RST 使会话进入 CLOSED。
	rst := testutil.BuildTCP(wanHost, extAddr, 80, mapped, packet.TCPRST, nil)
	if _, err := e.Process(rst, nat.DirInbound); err != nil {
		t.Fatalf("RST: %v", err)
	}
	// 关闭后的报文属于非法迁移。
	ack := testutil.BuildTCP(wanHost, extAddr, 80, mapped, packet.TCPACK, nil)
	if _, err := e.Process(ack, nat.DirInbound); !errors.Is(err, nat.ErrInvalidState) {
		t.Fatalf("err = %v, want ErrInvalidState", err)
	}
}

func TestPortConflictAndReuse(t *testing.T) {
	e := newEngine(t)
	// 两个不同源端口的会话应获得不同映射端口。
	p1 := testutil.BuildUDP(lanHost, wanHost, 5000, 53, []byte("a"))
	p2 := testutil.BuildUDP(lanHost, wanHost, 5001, 53, []byte("b"))
	o1, err := e.Process(p1, nat.DirOutbound)
	if err != nil {
		t.Fatalf("p1: %v", err)
	}
	o2, err := e.Process(p2, nat.DirOutbound)
	if err != nil {
		t.Fatalf("p2: %v", err)
	}
	q1, _ := packet.Parse(o1)
	q2, _ := packet.Parse(o2)
	if q1.SrcPort == q2.SrcPort {
		t.Fatalf("mapped ports collide: %d", q1.SrcPort)
	}
	// 端口范围耗尽时应报可区分错误。
	small, err := nat.NewEngine(nat.Config{ExternalAddr: extAddr, PortRangeMin: 40000, PortRangeMax: 40000, TableSize: 16})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer small.Close()
	a := testutil.BuildUDP(lanHost, wanHost, 6000, 53, []byte("x"))
	if _, err := small.Process(a, nat.DirOutbound); err != nil {
		t.Fatalf("first alloc: %v", err)
	}
	b := testutil.BuildUDP(lanHost, wanHost, 6001, 53, []byte("x"))
	if _, err := small.Process(b, nat.DirOutbound); !errors.Is(err, nat.ErrNoPortAvailable) {
		t.Fatalf("err = %v, want ErrNoPortAvailable", err)
	}
	// 回收后端口可复用。
	small.Reap()
	small.Close()
	small2, _ := nat.NewEngine(nat.Config{ExternalAddr: extAddr, PortRangeMin: 40000, PortRangeMax: 40000, TableSize: 16})
	defer small2.Close()
	if _, err := small2.Process(a, nat.DirOutbound); err != nil {
		t.Fatalf("reuse after restart: %v", err)
	}
}

func TestTimeoutReapReleasesPort(t *testing.T) {
	e, _ := nat.NewEngine(nat.Config{ExternalAddr: extAddr, PortRangeMin: 40000, PortRangeMax: 40000, TableSize: 16})
	// UDP 默认超时 3 分钟；这里直接构造后等待回收逻辑。
	pkt := testutil.BuildUDP(lanHost, wanHost, 6000, 53, []byte("x"))
	out, err := e.Process(pkt, nat.DirOutbound)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	p, _ := packet.Parse(out)
	mapped := p.SrcPort
	if st := e.Stats(); st.ActivePorts != 1 {
		t.Fatalf("ActivePorts = %d, want 1", st.ActivePorts)
	}
	// 模拟超时：关闭引擎必须释放端口，重启后可复现地分配到同一端口。
	e.Close()
	e2, _ := nat.NewEngine(nat.Config{ExternalAddr: extAddr, PortRangeMin: 40000, PortRangeMax: 40000, TableSize: 16})
	defer e2.Close()
	out2, err := e2.Process(pkt, nat.DirOutbound)
	if err != nil {
		t.Fatalf("after restart: %v", err)
	}
	p2, _ := packet.Parse(out2)
	if p2.SrcPort != mapped {
		t.Fatalf("port not reproducible after restart: got %d, want %d", p2.SrcPort, mapped)
	}
}

func TestConcurrentSessions(t *testing.T) {
	e := newEngine(t)
	const sessions = 64
	var wg sync.WaitGroup
	mapped := make([]uint16, sessions)
	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkt := testutil.BuildUDP(lanHost, wanHost, uint16(5000+i), 53, []byte("x"))
			out, err := e.Process(pkt, nat.DirOutbound)
			if err != nil {
				t.Errorf("session %d: %v", i, err)
				return
			}
			p, _ := packet.Parse(out)
			mapped[i] = p.SrcPort
		}(i)
	}
	wg.Wait()
	// 映射端口必须唯一。
	seen := map[uint16]int{}
	for _, m := range mapped {
		seen[m]++
	}
	for m, n := range seen {
		if n != 1 {
			t.Fatalf("port %d assigned %d times", m, n)
		}
	}
	st := e.Stats()
	if st.Conntrack.Entries != sessions || st.ActivePorts != sessions {
		t.Fatalf("stats: entries=%d ports=%d, want %d", st.Conntrack.Entries, st.ActivePorts, sessions)
	}
	if st.PacketsIn != sessions || st.PacketsOut != sessions || st.Rejected != 0 {
		t.Fatalf("counters: %+v", st)
	}
}

func TestConcurrentSameFlow(t *testing.T) {
	e := newEngine(t)
	// 同一五元组并发建连：只能产生一条会话与一个映射端口。
	var wg sync.WaitGroup
	ports := make([]uint16, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkt := testutil.BuildUDP(lanHost, wanHost, 5000, 53, []byte("x"))
			out, err := e.Process(pkt, nat.DirOutbound)
			if err != nil {
				t.Errorf("Process: %v", err)
				return
			}
			p, _ := packet.Parse(out)
			ports[i] = p.SrcPort
		}(i)
	}
	wg.Wait()
	for _, m := range ports[1:] {
		if m != ports[0] {
			t.Fatalf("same flow mapped to different ports: %v", ports)
		}
	}
	st := e.Stats()
	if st.Conntrack.Entries != 1 || st.ActivePorts != 1 {
		t.Fatalf("stats: entries=%d ports=%d", st.Conntrack.Entries, st.ActivePorts)
	}
}
