package natct

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
)

// splitFragments 把一个完整数据报拆成指定大小的 IP 分片
func splitFragments(dgram []byte, fragSize int) [][]byte {
	ihl := int(dgram[0]&0x0f) * 4
	payload := dgram[ihl:]
	id := be16(dgram[4:6])
	proto := Protocol(dgram[9])
	var frags [][]byte
	for off := 0; off < len(payload); off += fragSize {
		end := off + fragSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		flags := uint16(0)
		if end < len(payload) {
			flags = 0x2000
		}
		flags |= uint16(off / 8)
		s, _ := netip.AddrFromSlice(dgram[12:16])
		d, _ := netip.AddrFromSlice(dgram[16:20])
		f := buildIPv4(proto, s.Unmap(), d.Unmap(), id, flags, chunk)
		frags = append(frags, f)
	}
	return frags
}

func TestFragments_OutOfOrderAndDuplicate(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	p := NewPipe(e)
	client, server := ip4("10.4.0.1"), ip4("198.51.100.30")

	// 28 字节 UDP 负载，按 16 字节拆两片
	full := udpPacket(client, server, 40000, 53, make([]byte, 24))
	frags := splitFragments(full, 16)
	if len(frags) != 2 {
		t.Fatalf("want 2 fragments, got %d", len(frags))
	}

	// 乱序：先发第二片，应被缓存无输出
	got, err := p.Process(frags[1])
	if err != nil || len(got) != 0 {
		t.Fatalf("second fragment first: got=%d err=%v", len(got), err)
	}
	// 重复第二片：仍无输出且不报错
	got, err = p.Process(frags[1])
	if err != nil || len(got) != 0 {
		t.Fatalf("duplicate fragment: got=%d err=%v", len(got), err)
	}
	// 第一片到达：重组、NAT 成功，输出仍是 2 片
	got, err = p.Process(frags[0])
	if err != nil {
		t.Fatalf("reassembly: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 output fragments, got %d", len(got))
	}

	// 重组结果必须能整体解析、校验和有效、SNAT 正确
	out := reassembleForTest(got)
	pp, err := parsePacket(out)
	if err != nil {
		t.Fatalf("reassembled output invalid: %v", err)
	}
	if pp.SrcIP.String() != "203.0.113.1" || pp.DstIP != server || pp.DstPort != 53 {
		t.Fatalf("bad NAT on reassembled: %+v", pp.tuple())
	}

	// 重组完成后分组应已删除；再来一个重复首片不应重建脏会话
	_, _ = p.Process(frags[0])
	if got := e.table.Stats().TotalCreated; got != 1 {
		t.Fatalf("fragment replay created extra session: %d", got)
	}
}

func TestFragments_MissingNeverDelivers(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	p := NewPipe(e)
	client, server := ip4("10.4.0.2"), ip4("198.51.100.31")
	full := udpPacket(client, server, 40001, 53, make([]byte, 40))
	frags := splitFragments(full, 16)

	// 只发第 1、3 片，中间缺失，永远不应交付
	if got, _ := p.Process(frags[0]); len(got) != 0 {
		t.Fatalf("partial delivered: %d", len(got))
	}
	if got, _ := p.Process(frags[2]); len(got) != 0 {
		t.Fatalf("partial delivered: %d", len(got))
	}
	if e.table.Len() != 0 {
		t.Fatalf("incomplete fragments must not create session")
	}
	if p.reasm.Reap() != 0 {
		t.Fatalf("fresh incomplete group should remain buffered")
	}
}

func reassembleForTest(frags [][]byte) []byte {
	var payload []byte
	for _, f := range frags {
		ihl := int(f[0]&0x0f) * 4
		payload = append(payload, f[ihl:]...)
	}
	base := frags[0]
	ihl := int(base[0]&0x0f) * 4
	dgram := append(append([]byte(nil), base[:ihl]...), payload...)
	return dgram
}

// 并发建会话：映射必须唯一，统计与会话表一致
func TestConcurrent_SessionsUniquePorts(t *testing.T) {
	cfg := baseCfg()
	cfg.PortMax = 20999
	cfg.MaxSessions = 1000
	e, done := testEngine(t, cfg)
	defer done()

	const n = 200
	var wg sync.WaitGroup
	ports := make([]uint16, n)
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			src := ip4(fmt.Sprintf("10.5.%d.%d", i/250, 1+i%250))
			out, _, err := e.Handle(udpPacket(src, ip4("198.51.100.40"), uint16(40000+i%20000), 53, nil))
			if err != nil {
				errs <- err
				return
			}
			pp, _ := parsePacket(out)
			ports[i] = pp.SrcPort
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent create: %v", err)
	}

	seen := map[uint16]int{}
	for _, mp := range ports {
		seen[mp]++
	}
	if len(seen) != n {
		t.Fatalf("port mapping not unique: %d sessions but %d distinct ports", n, len(seen))
	}
	if e.table.Len() != n {
		t.Fatalf("active count mismatch: %d want %d", e.table.Len(), n)
	}
	st := e.table.Stats()
	if st.ActiveSessions != n || st.TotalCreated != uint64(n) || st.TotalPackets != uint64(n) {
		t.Fatalf("stats inconsistent under concurrency: %+v", st)
	}
}

// 结果可复现：顺序创建时端口按确定性游标分配，回收后可复用
func TestPortAlloc_DeterministicAndReuse(t *testing.T) {
	a := NewPortAllocator(20000, 20009)
	p1, _ := a.Allocate(ProtoUDP, 0)
	p2, _ := a.Allocate(ProtoUDP, 0)
	if p1 != 20000 || p2 != 20001 {
		t.Fatalf("unexpected deterministic alloc: %d %d", p1, p2)
	}
	a.Release(ProtoUDP, p1)
	p3, _ := a.Allocate(ProtoUDP, 0)
	if p3 != 20002 { // 游标只前进，不立即回填
		t.Fatalf("cursor should move forward: %d", p3)
	}
	// 协议间端口空间独立
	pt, _ := a.Allocate(ProtoTCP, 0)
	if pt != 20000 {
		t.Fatalf("TCP should have independent space: %d", pt)
	}
	// 首选端口 20000 已占用时应跳过并另分配
	p4, err := a.Allocate(ProtoTCP, 20000)
	if err != nil {
		t.Fatalf("preferred conflict: %v", err)
	}
	if p4 == 20000 {
		t.Fatal("allocator returned a port already in use")
	}
	// 耗尽时返回可区分错误
	b := NewPortAllocator(30000, 30001)
	b.Allocate(ProtoTCP, 0)
	b.Allocate(ProtoTCP, 0)
	if _, err := b.Allocate(ProtoTCP, 0); err != ErrNoPortsAvailable {
		t.Fatalf("want ErrNoPortsAvailable, got %v", err)
	}
}

// TCP 报文分片：首片含 TCP 头，重组后才能完成状态机与改写
func TestFragments_TCPFirstFragment(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	pipe := NewPipe(e)
	client, server := ip4("10.4.0.9"), ip4("198.51.100.39")

	// 20 字节 TCP 头 + 24 负载 = 44 字节 IP 负载，按 16 拆 3 片
	l4 := buildTCP(client, server, 50000, 443, tcpSYN, 1, 0, make([]byte, 24))
	full := buildIPv4(ProtoTCP, client, server, 0x1234, 0, l4)
	finalizeL4(ProtoTCP, client, server, full)
	frags := splitFragments(full, 16)

	// 乱序喂入 3、2、1
	var out [][]byte
	var err error
	out, err = pipe.Process(frags[2])
	if err != nil || len(out) != 0 {
		t.Fatalf("frag3: %v %d", err, len(out))
	}
	out, err = pipe.Process(frags[1])
	if err != nil || len(out) != 0 {
		t.Fatalf("frag2: %v %d", err, len(out))
	}
	out, err = pipe.Process(frags[0])
	if err != nil {
		t.Fatalf("frag1: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 out fragments, got %d", len(out))
	}
	reassembled := reassembleForTest(out)
	pp, err := parsePacket(reassembled)
	if err != nil {
		t.Fatalf("reassembled tcp invalid: %v", err)
	}
	if pp.SrcIP.String() != "203.0.113.1" || pp.DstPort != 443 || pp.Flags != tcpSYN {
		t.Fatalf("bad NAT/flags: %+v flags=%x", pp.tuple(), pp.Flags)
	}
}

// 相同偏移但内容不同的重复分片必须被拒绝，且不污染会话
func TestFragments_ConflictingDuplicateRejected(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	pipe := NewPipe(e)
	client, server := ip4("10.4.0.10"), ip4("198.51.100.40")
	full := udpPacket(client, server, 40000, 53, make([]byte, 24))
	frags := splitFragments(full, 16)

	if _, err := pipe.Process(frags[0]); err != nil {
		t.Fatal(err)
	}
	evil := append([]byte(nil), frags[0]...)
	evil[len(evil)-1] ^= 0xff // 篡改负载，IP 校验和对该分片仍有效（仅覆盖头）
	if _, err := pipe.Process(evil); err != ErrMalformedPacket {
		t.Fatalf("want ErrMalformedPacket, got %v", err)
	}
	if e.table.Len() != 0 {
		t.Fatal("conflicting fragments must not establish a session")
	}
}
