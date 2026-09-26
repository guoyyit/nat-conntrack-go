package natct

import (
	"net/netip"
)

func ip4(a string) netip.Addr { return netip.MustParseAddr(a) }

// buildIPv4 构造一个带正确校验和的 IPv4 报文
func buildIPv4(proto Protocol, src, dst netip.Addr, id, fragFlags uint16, l4 []byte) []byte {
	ihl := 20
	tot := ihl + len(l4)
	b := make([]byte, tot)
	b[0] = 0x45
	b[1] = 0
	b[2] = byte(tot >> 8)
	b[3] = byte(tot)
	b[4] = byte(id >> 8)
	b[5] = byte(id)
	b[6] = byte(fragFlags >> 8)
	b[7] = byte(fragFlags)
	b[8] = 64
	b[9] = byte(proto)
	src4 := src.As4()
	dst4 := dst.As4()
	copy(b[12:16], src4[:])
	copy(b[16:20], dst4[:])
	sum := ipChecksum(b[:ihl])
	b[10] = byte(sum >> 8)
	b[11] = byte(sum)
	copy(b[ihl:], l4)
	return b
}

func buildTCP(src, dst netip.Addr, sport, dport uint16, flags uint8, seq, ack uint32, payload []byte) []byte {
	l4 := make([]byte, 20+len(payload))
	putBe16(l4[0:2], sport)
	putBe16(l4[2:4], dport)
	putBe32(l4[4:8], seq)
	putBe32(l4[8:12], ack)
	l4[12] = 5 << 4
	l4[13] = flags
	putBe16(l4[14:16], 65535)
	copy(l4[20:], payload)
	return l4
}

func buildUDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	putBe16(l4[0:2], sport)
	putBe16(l4[2:4], dport)
	putBe16(l4[4:6], uint16(8+len(payload)))
	copy(l4[8:], payload)
	return l4
}

func buildICMP(icmpType uint8, ident uint16, seq uint16, payload []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	l4[0] = icmpType
	putBe16(l4[4:6], ident)
	putBe16(l4[6:8], seq)
	copy(l4[8:], payload)
	sum := csumFold(csum(l4))
	putBe16(l4[2:4], sum)
	return l4
}

func putBe32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// finalizeL4 填入 TCP/UDP 校验和
func finalizeL4(proto Protocol, src, dst netip.Addr, dgram []byte) {
	ihl := int(dgram[0]&0x0f) * 4
	l4 := dgram[ihl:]
	p := &Packet{Proto: proto, L3: dgram}
	switch proto {
	case ProtoTCP:
		sum := computeL4Checksum(p, l4)
		putBe16(l4[16:18], sum)
	case ProtoUDP:
		sum := computeL4Checksum(p, l4)
		if sum == 0 {
			sum = 0xffff
		}
		putBe16(l4[6:8], sum)
	}
}

func tcpPacket(src, dst netip.Addr, sport, dport uint16, flags uint8, seq, ack uint32) []byte {
	l4 := buildTCP(src, dst, sport, dport, flags, seq, ack, nil)
	d := buildIPv4(ProtoTCP, src, dst, 0, 0, l4)
	finalizeL4(ProtoTCP, src, dst, d)
	return d
}

func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	l4 := buildUDP(src, dst, sport, dport, payload)
	d := buildIPv4(ProtoUDP, src, dst, 0, 0, l4)
	finalizeL4(ProtoUDP, src, dst, d)
	return d
}

func icmpPacket(src, dst netip.Addr, icmpType, ident uint16, payload []byte) []byte {
	t := uint8(8)
	if icmpType == 0 {
		t = 0
	}
	l4 := buildICMP(t, ident, 1, payload)
	return buildIPv4(ProtoICMP, src, dst, 0, 0, l4)
}
