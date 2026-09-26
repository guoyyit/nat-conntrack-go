package natct

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// 高并发双向流量：多 goroutine 同时建会话并互发回程报文，
// 验证无丢失/重复计数、映射唯一、无竞态。
func TestConcurrent_BidirectionalStress(t *testing.T) {
	cfg := baseCfg()
	cfg.PortMax = 21999
	cfg.MaxSessions = 2000
	e, done := testEngine(t, cfg)
	defer done()

	const pairs = 300
	var wg sync.WaitGroup
	errs := make(chan error, pairs*2)

	// 建立会话（去程）
	mapped := make([]uint16, pairs)
	wg.Add(pairs)
	for i := 0; i < pairs; i++ {
		i := i
		go func() {
			defer wg.Done()
			src := ip4(fmt.Sprintf("10.9.%d.%d", i/250, 1+i%250))
			out, _, err := e.Handle(udpPacket(src, ip4("198.51.100.70"), uint16(40000+i%20000), 53, []byte("q")))
			if err != nil {
				errs <- err
				return
			}
			pp, _ := parsePacket(out)
			mapped[i] = pp.SrcPort
		}()
	}
	wg.Wait()

	st := e.table.Stats()
	if st.ActiveSessions != pairs || st.TotalPackets != uint64(pairs) {
		t.Fatalf("after create: %+v", st)
	}

	// 回程流量并发
	wg.Add(pairs)
	for i := 0; i < pairs; i++ {
		i := i
		go func() {
			defer wg.Done()
			src := ip4(fmt.Sprintf("10.9.%d.%d", i/250, 1+i%250))
			back := udpPacket(ip4("198.51.100.70"), cfg.PublicIP, 53, mapped[i], []byte("a"))
			out, dir, err := e.Handle(back)
			if err != nil || dir != DirReply {
				errs <- fmt.Errorf("reply i=%d dir=%v: %w", i, dir, err)
				return
			}
			pp, _ := parsePacket(out)
			if pp.DstIP != src || pp.DstPort != uint16(40000+i%20000) {
				errs <- fmt.Errorf("reply i=%d mismatched dst: %+v", i, pp.tuple())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	st = e.table.Stats()
	if st.TotalPackets != uint64(pairs*2) || st.ActiveSessions != pairs {
		t.Fatalf("after reply: %+v", st)
	}
}

// 不支持的 ICMP 类型应给出可区分原因，且不影响后续处理
func TestICMP_UnsupportedType(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	client, server := ip4("10.10.0.1"), ip4("198.51.100.80")

	l4 := buildICMP(3, 0, 0, []byte("unreachable")) // destination unreachable
	raw := buildIPv4(ProtoICMP, client, server, 0, 0, l4)
	if _, _, err := e.Handle(raw); !errors.Is(err, ErrProtocolUnsupported) {
		t.Fatalf("want unsupported icmp, got %v", err)
	}
	if _, _, err := e.Handle(udpPacket(client, server, 40000, 53, nil)); err != nil {
		t.Fatalf("subsequent packet failed: %v", err)
	}
}
