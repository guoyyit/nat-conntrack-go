package nat_test

import (
	"testing"

	"github.com/guoyyit/nat-conntrack-go/internal/testutil"
	"github.com/guoyyit/nat-conntrack-go/nat"
	"github.com/guoyyit/nat-conntrack-go/packet"
	"github.com/guoyyit/nat-conntrack-go/pipe"
)

// TestPipelineEndToEnd 用两条内存管道模拟网卡收发：
// LAN->引擎->WAN 与 WAN->引擎->LAN，验证双向流量正确回流。
func TestPipelineEndToEnd(t *testing.T) {
	e := newEngine(t)
	lanIn, wanOut := pipe.New(16), pipe.New(16) // 去程
	wanIn, lanOut := pipe.New(16), pipe.New(16) // 回程

	// 去程：内网主机发起 UDP 会话。
	lanIn.Send(testutil.BuildUDP(lanHost, wanHost, 5353, 53, []byte("dns")))
	data, ok := lanIn.Recv()
	if !ok {
		t.Fatal("lanIn empty")
	}
	out, err := e.Process(data, nat.DirOutbound)
	if err != nil {
		t.Fatalf("outbound: %v", err)
	}
	if !wanOut.Send(out) {
		t.Fatal("wanOut send failed")
	}

	// 对端看到的报文源地址应为出口地址。
	wire, _ := wanOut.Recv()
	p, _ := packet.Parse(wire)
	if p.SrcAddr != extAddr {
		t.Fatalf("on-wire src = %v, want %v", p.SrcAddr, extAddr)
	}

	// 回程：对端应答，经引擎后回到内网主机。
	wanIn.Send(testutil.BuildUDP(wanHost, extAddr, 53, p.SrcPort, []byte("answer")))
	data, _ = wanIn.Recv()
	in, err := e.Process(data, nat.DirInbound)
	if err != nil {
		t.Fatalf("inbound: %v", err)
	}
	lanOut.Send(in)
	wire, _ = lanOut.Recv()
	q, _ := packet.Parse(wire)
	if q.DstAddr != lanHost || q.DstPort != 5353 {
		t.Fatalf("reply not delivered to lan host: %v:%d", q.DstAddr, q.DstPort)
	}
	if string(q.Payload) != "answer" {
		t.Fatalf("payload = %q", q.Payload)
	}
}
