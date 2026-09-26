package conntrack_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/guoyyit/nat-conntrack-go/conntrack"
	"github.com/guoyyit/nat-conntrack-go/internal/testutil"
)

func tcpTuple(sport uint16) conntrack.Tuple {
	return conntrack.Tuple{
		Protocol: conntrack.ProtocolTCP,
		SrcAddr:  testutil.Addr("10.0.0.1"),
		DstAddr:  testutil.Addr("8.8.8.8"),
		SrcPort:  sport,
		DstPort:  80,
	}
}

func replyOf(orig conntrack.Tuple, mapped uint16) conntrack.Tuple {
	return conntrack.Tuple{
		Protocol: orig.Protocol,
		SrcAddr:  orig.DstAddr,
		DstAddr:  testutil.Addr("203.0.113.1"),
		SrcPort:  orig.DstPort,
		DstPort:  mapped,
	}
}

const (
	syn = 0x02
	ack = 0x10
	fin = 0x01
	rst = 0x04
)

func TestStateMachineTCP(t *testing.T) {
	ct := conntrack.NewTable(16)
	orig := tcpTuple(12345)
	reply := replyOf(orig, 40001)
	now := time.Now()

	if _, err := ct.Create(orig, reply, time.Minute); err != nil {
		t.Fatalf("Create: %v", err)
	}
	e, _ := ct.Update(orig, syn, 60, now)
	if e.State != conntrack.StateNew {
		t.Fatalf("after SYN: %v", e.State)
	}
	// 重复 SYN（重传）不应破坏状态。
	e, _ = ct.Update(orig, syn, 60, now)
	if e.State != conntrack.StateNew {
		t.Fatalf("after dup SYN: %v", e.State)
	}
	e, _ = ct.Update(reply, syn|ack, 60, now)
	if e.State != conntrack.StateEstablished {
		t.Fatalf("after SYN-ACK: %v", e.State)
	}
	e, _ = ct.Update(orig, ack, 60, now)
	if e.State != conntrack.StateEstablished {
		t.Fatalf("after ACK: %v", e.State)
	}
	e, _ = ct.Update(orig, fin|ack, 60, now)
	if e.State != conntrack.StateClosing {
		t.Fatalf("after FIN: %v", e.State)
	}
	e, _ = ct.Update(reply, fin|ack, 60, now)
	if e.State != conntrack.StateClosed {
		t.Fatalf("after reply FIN: %v", e.State)
	}
	// 已关闭会话上的报文属于非法迁移。
	if _, err := ct.Update(orig, ack, 60, now); err != conntrack.ErrInvalidTransition {
		t.Fatalf("err = %v, want ErrInvalidTransition", err)
	}
}

func TestOutOfOrderACK(t *testing.T) {
	ct := conntrack.NewTable(16)
	orig := tcpTuple(2222)
	reply := replyOf(orig, 40002)
	now := time.Now()
	ct.Create(orig, reply, time.Minute)
	// 乱序：ACK 先于 SYN-ACK 到达，应宽容归入会话而非错配。
	e, err := ct.Update(orig, ack, 60, now)
	if err != nil || e.State != conntrack.StateEstablished {
		t.Fatalf("out-of-order ACK: state=%v err=%v", e.State, err)
	}
}

func TestUDPReplyEstablishes(t *testing.T) {
	ct := conntrack.NewTable(16)
	orig := conntrack.Tuple{
		Protocol: conntrack.ProtocolUDP,
		SrcAddr:  testutil.Addr("10.0.0.1"), DstAddr: testutil.Addr("8.8.8.8"),
		SrcPort: 5353, DstPort: 53,
	}
	reply := replyOf(orig, 40003)
	now := time.Now()
	ct.Create(orig, reply, time.Minute)
	e, _ := ct.Update(orig, 0, 60, now)
	if e.State != conntrack.StateNew {
		t.Fatalf("after outbound UDP: %v", e.State)
	}
	e, _ = ct.Update(reply, 0, 60, now)
	if e.State != conntrack.StateEstablished {
		t.Fatalf("after reply UDP: %v", e.State)
	}
}

func TestTimeoutReap(t *testing.T) {
	ct := conntrack.NewTable(16)
	now := time.Now()
	for i := 0; i < 3; i++ {
		orig := tcpTuple(uint16(1000 + i))
		ct.Create(orig, replyOf(orig, uint16(40000+i)), time.Second)
	}
	if ct.Len() != 3 {
		t.Fatalf("Len = %d, want 3", ct.Len())
	}
	// 只让其中一条保持活跃。
	ct.Update(tcpTuple(1000), ack, 60, now.Add(2*time.Second))
	n := ct.Reap(now.Add(3 * time.Second))
	if n != 2 || ct.Len() != 1 {
		t.Fatalf("reaped %d, len %d; want 2/1", n, ct.Len())
	}
	st := ct.Stats()
	if st.Expired != 2 || st.Entries != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestCapacityEvictsLRU(t *testing.T) {
	ct := conntrack.NewTable(2)
	now := time.Now()
	ct.Create(tcpTuple(1), replyOf(tcpTuple(1), 40001), time.Hour)
	ct.Create(tcpTuple(2), replyOf(tcpTuple(2), 40002), time.Hour)
	// 让 2 号更新鲜，再建第三条应淘汰最旧的 1 号。
	ct.Update(tcpTuple(2), ack, 60, now.Add(time.Minute))
	if _, err := ct.Create(tcpTuple(3), replyOf(tcpTuple(3), 40003), time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := ct.Get(tcpTuple(1)); ok {
		t.Fatal("LRU entry should have been evicted")
	}
	if ct.Len() != 2 {
		t.Fatalf("Len = %d, want 2", ct.Len())
	}
	if ct.Stats().Evicted != 1 {
		t.Fatalf("Evicted = %d, want 1", ct.Stats().Evicted)
	}
}

func TestCreateIdempotent(t *testing.T) {
	ct := conntrack.NewTable(16)
	orig := tcpTuple(9)
	e1, _ := ct.Create(orig, replyOf(orig, 40009), time.Minute)
	e2, _ := ct.Create(orig, replyOf(orig, 40009), time.Minute)
	if e1 != e2 || ct.Len() != 1 {
		t.Fatalf("duplicate create must be idempotent: len=%d", ct.Len())
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	ct := conntrack.NewTable(4096)
	var wg sync.WaitGroup
	now := time.Now()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				sport := uint16(g*200 + i + 1)
				orig := tcpTuple(sport)
				ct.Create(orig, replyOf(orig, 40000+sport), time.Minute)
				ct.Update(orig, syn, 60, now)
				ct.Get(orig)
			}
		}(g)
	}
	wg.Wait()
	if ct.Len() != 1600 {
		t.Fatalf("Len = %d, want 1600", ct.Len())
	}
	st := ct.Stats()
	if st.Created != 1600 || st.Entries != 1600 {
		t.Fatalf("stats mismatch: %+v", st)
	}
}

func TestStatsConsistency(t *testing.T) {
	ct := conntrack.NewTable(4)
	now := time.Now()
	for i := 0; i < 4; i++ {
		ct.Create(tcpTuple(uint16(i+1)), replyOf(tcpTuple(uint16(i+1)), uint16(40001+i)), time.Second)
	}
	ct.Reap(now.Add(2 * time.Second))
	st := ct.Stats()
	if st.Entries != 0 || st.Expired != 4 || st.Capacity != 4 {
		t.Fatalf("stats: %+v", st)
	}
	// 容量满且全部未超时但可被 LRU 淘汰时，不应失败。
	for i := 0; i < 4; i++ {
		ct.Create(tcpTuple(uint16(i+10)), replyOf(tcpTuple(uint16(i+10)), uint16(41001+i)), time.Hour)
	}
	if _, err := ct.Create(tcpTuple(99), replyOf(tcpTuple(99), 41099), time.Hour); err != nil {
		t.Fatalf("Create with LRU eviction: %v", err)
	}
	if got := fmt.Sprint(ct.Stats().Entries); got != "4" {
		t.Fatalf("Entries = %s, want 4", got)
	}
}
