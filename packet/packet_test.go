package packet_test

import (
	"testing"

	"github.com/guoyyit/nat-conntrack-go/internal/testutil"
	"github.com/guoyyit/nat-conntrack-go/packet"
)

func TestParseTCP(t *testing.T) {
	data := testutil.BuildTCP(testutil.Addr("10.0.0.1"), testutil.Addr("8.8.8.8"), 12345, 80, packet.TCPSYN, nil)
	p, err := packet.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Protocol != packet.ProtocolTCP || p.SrcPort != 12345 || p.DstPort != 80 {
		t.Fatalf("unexpected parse result: %+v", p)
	}
	if p.TCPFlags != packet.TCPSYN {
		t.Fatalf("TCPFlags = %#x, want SYN", p.TCPFlags)
	}
}

func TestSerializeRewriteChecksumValid(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "icmp"} {
		var data []byte
		switch proto {
		case "tcp":
			data = testutil.BuildTCP(testutil.Addr("10.0.0.1"), testutil.Addr("8.8.8.8"), 12345, 80, packet.TCPACK, []byte("hello"))
		case "udp":
			data = testutil.BuildUDP(testutil.Addr("10.0.0.1"), testutil.Addr("8.8.8.8"), 12345, 53, []byte("dns-query"))
		case "icmp":
			data = testutil.BuildICMPEcho(testutil.Addr("10.0.0.1"), testutil.Addr("8.8.8.8"), 777, false, []byte("ping"))
		}
		p, err := packet.Parse(data)
		if err != nil {
			t.Fatalf("%s Parse: %v", proto, err)
		}
		p.SrcAddr = testutil.Addr("203.0.113.1")
		p.SrcPort = 40001
		out, err := p.Serialize()
		if err != nil {
			t.Fatalf("%s Serialize: %v", proto, err)
		}
		// 改写后的报文必须能再次通过解析（含校验和验证）。
		q, err := packet.Parse(out)
		if err != nil {
			t.Fatalf("%s re-Parse after rewrite: %v", proto, err)
		}
		if q.SrcAddr != testutil.Addr("203.0.113.1") || q.SrcPort != 40001 {
			t.Fatalf("%s rewrite not applied: %+v", proto, q)
		}
	}
}

func TestParseBadChecksum(t *testing.T) {
	data := testutil.BuildTCP(testutil.Addr("10.0.0.1"), testutil.Addr("8.8.8.8"), 1, 2, packet.TCPSYN, nil)
	data[10] ^= 0xff // 破坏 IP 首部校验和
	if _, err := packet.Parse(data); err != packet.ErrChecksumInvalid {
		t.Fatalf("err = %v, want ErrChecksumInvalid", err)
	}
}

func TestParseMalformed(t *testing.T) {
	if _, err := packet.Parse([]byte{0x45, 0x00}); err != packet.ErrMalformed {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	data := testutil.BuildUDP(testutil.Addr("10.0.0.1"), testutil.Addr("8.8.8.8"), 1, 2, nil)
	data[0] = 0x65 // 版本改为 6
	if _, err := packet.Parse(data); err != packet.ErrNotIPv4 {
		t.Fatalf("err = %v, want ErrNotIPv4", err)
	}
}

func TestFragmentParse(t *testing.T) {
	data := testutil.BuildUDP(testutil.Addr("10.0.0.1"), testutil.Addr("8.8.8.8"), 5000, 53, make([]byte, 64))
	frags := testutil.Fragment(data, 24)
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}
	// 首片：带传输层首部。
	p0, err := packet.Parse(frags[0])
	if err != nil {
		t.Fatalf("first fragment Parse: %v", err)
	}
	if !p0.IsFragment() || !p0.IsFirstFragment() || p0.SrcPort != 5000 {
		t.Fatalf("first fragment: %+v", p0)
	}
	// 后续分片：无传输层首部。
	p1, err := packet.Parse(frags[1])
	if err != nil {
		t.Fatalf("non-first fragment Parse: %v", err)
	}
	if !p1.IsFragment() || p1.IsFirstFragment() {
		t.Fatalf("non-first fragment misclassified: %+v", p1)
	}
	// 非首片只做 IP 首部改写，序列化后 IP 校验和仍须有效。
	p1.SrcAddr = testutil.Addr("203.0.113.1")
	out, err := p1.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if _, err := packet.Parse(out); err != nil {
		t.Fatalf("re-Parse rewritten fragment: %v", err)
	}
}
