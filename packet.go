package natct

import (
	"net/netip"
)

// Protocol 标识传输层协议
type Protocol uint8

const (
	ProtoICMP Protocol = 1
	ProtoTCP  Protocol = 6
	ProtoUDP  Protocol = 17
)

func (p Protocol) String() string {
	switch p {
	case ProtoICMP:
		return "ICMP"
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

// Direction 表示报文相对会话的方向
type Direction uint8

const (
	DirInvalid Direction = iota
	DirOriginal
	DirReply
)

func (d Direction) String() string {
	switch d {
	case DirOriginal:
		return "original"
	case DirReply:
		return "reply"
	default:
		return "invalid"
	}
}

// TCP flag bits
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// Packet 是一个 IPv4 报文的解析视图。
// 所有切片都指向构造时复制的独立缓冲，改写不会影响输入。
type Packet struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Proto    Protocol
	L3       []byte // IP 头起始（整个数据报缓冲）
	L4       []byte // 传输层头起始（首片且非分片时有效）
	Payload  []byte // 传输层负载
	FragID   uint16 // IPv4 Identification
	FragOff  uint16 // 以 8 字节为单位的片偏移
	MoreFrag bool
	Flags    uint8 // TCP flags
	ICMPType uint8
	ICMPCode uint8

	ihl  int // IP 头长度
	tot  int // IP 总长度
	l4hl int // 传输层头长度
}

// FiveTuple 五元组
type FiveTuple struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	Proto   Protocol
	SrcPort uint16
	DstPort uint16
}

func (p *Packet) tuple() FiveTuple {
	return FiveTuple{SrcIP: p.SrcIP, DstIP: p.DstIP, Proto: p.Proto, SrcPort: p.SrcPort, DstPort: p.DstPort}
}

// parsePacket 解析并校验一个 IPv4 报文。
// 可区分的错误：ErrMalformedPacket / ErrChecksumInvalid / ErrProtocolUnsupported。
func parsePacket(raw []byte) (*Packet, error) {
	if len(raw) < 20 {
		return nil, ErrMalformedPacket
	}
	version := raw[0] >> 4
	if version != 4 {
		return nil, ErrProtocolUnsupported
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || len(raw) < ihl {
		return nil, ErrMalformedPacket
	}
	tot := int(uint16(raw[2])<<8 | uint16(raw[3]))
	if tot < ihl || tot > len(raw) {
		return nil, ErrMalformedPacket
	}
	if ipChecksum(raw[:ihl]) != 0 {
		return nil, ErrChecksumInvalid
	}

	proto := Protocol(raw[9])
	switch proto {
	case ProtoTCP, ProtoUDP, ProtoICMP:
	default:
		return nil, ErrProtocolUnsupported
	}

	buf := make([]byte, tot)
	copy(buf, raw[:tot])

	srcIP, _ := netip.AddrFromSlice(buf[12:16])
	dstIP, _ := netip.AddrFromSlice(buf[16:20])
	srcIP = srcIP.Unmap()
	dstIP = dstIP.Unmap()

	flagsFrag := uint16(buf[6])<<8 | uint16(buf[7])
	moreFrag := flagsFrag&0x2000 != 0
	fragOff := flagsFrag & 0x1fff

	p := &Packet{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Proto:    proto,
		L3:       buf,
		FragID:   uint16(buf[4])<<8 | uint16(buf[5]),
		FragOff:  fragOff,
		MoreFrag: moreFrag,
		ihl:      ihl,
		tot:      tot,
	}

	// 非首片没有传输层头，只能做 IP 层归属
	if fragOff > 0 {
		return p, nil
	}

	l4 := buf[ihl:tot]
	p.L4 = l4
	// 首片但还有后续分片（MF=1）：L4 校验和覆盖整个原始报文，
	// 单片无法验证，留给重组后整体校验。
	if moreFrag {
		if err := p.parseTransportHeader(l4); err != nil {
			return nil, err
		}
		return p, nil
	}
	if err := p.parseTransport(l4); err != nil {
		return nil, err
	}
	return p, nil
}

// parseTransportHeader 仅解析端口/标志，不做整体 L4 校验和与完整头长度验证。
// 用于 MF=1 的首片：其负载只是原始报文的一段，L4 头本身可能都不完整，
// 完整校验统一在重组后进行。
func (p *Packet) parseTransportHeader(l4 []byte) error {
	switch p.Proto {
	case ProtoTCP:
		if len(l4) < 14 { // 至少要读到端口与 flags
			return ErrMalformedPacket
		}
		p.SrcPort = be16(l4[0:2])
		p.DstPort = be16(l4[2:4])
		p.Flags = l4[13]
		if len(l4) >= 20 {
			p.l4hl = int(l4[12]>>4) * 4
		}
	case ProtoUDP:
		if len(l4) < 8 {
			return ErrMalformedPacket
		}
		p.SrcPort = be16(l4[0:2])
		p.DstPort = be16(l4[2:4])
		p.l4hl = 8
	case ProtoICMP:
		if len(l4) < 8 {
			return ErrMalformedPacket
		}
		p.ICMPType = l4[0]
		p.ICMPCode = l4[1]
		p.l4hl = 8
		id := be16(l4[4:6])
		switch p.ICMPType {
		case 8:
			p.DstPort = id
		case 0:
			p.SrcPort = id
		default:
			return ErrProtocolUnsupported
		}
	}
	return nil
}

func (p *Packet) parseTransport(l4 []byte) error {
	switch p.Proto {
	case ProtoTCP:
		if len(l4) < 20 {
			return ErrMalformedPacket
		}
		p.SrcPort = be16(l4[0:2])
		p.DstPort = be16(l4[2:4])
		p.l4hl = int(l4[12]>>4) * 4
		if p.l4hl < 20 || p.l4hl > len(l4) {
			return ErrMalformedPacket
		}
		p.Flags = l4[13]
		if !verifyL4Checksum(p, l4) {
			return ErrChecksumInvalid
		}
		p.Payload = l4[p.l4hl:]
	case ProtoUDP:
		if len(l4) < 8 {
			return ErrMalformedPacket
		}
		p.SrcPort = be16(l4[0:2])
		p.DstPort = be16(l4[2:4])
		// IPv4 UDP 校验和允许为 0（表示不校验）
		if be16(l4[6:8]) != 0 && !verifyL4Checksum(p, l4) {
			return ErrChecksumInvalid
		}
		p.l4hl = 8
		p.Payload = l4[8:]
	case ProtoICMP:
		if len(l4) < 8 {
			return ErrMalformedPacket
		}
		p.ICMPType = l4[0]
		p.ICMPCode = l4[1]
		if csumFold(csum(l4)) != 0 {
			return ErrChecksumInvalid
		}
		p.l4hl = 8
		p.Payload = l4[8:]
		id := be16(l4[4:6])
		switch p.ICMPType {
		case 8: // echo request：id 归入目的端口位
			p.DstPort = id
		case 0: // echo reply：id 归入源端口位
			p.SrcPort = id
		default:
			return ErrProtocolUnsupported
		}
	}
	return nil
}

// Bytes 返回改写后的完整数据报字节
func (p *Packet) Bytes() []byte { return p.L3[:p.tot] }

// ---------- 校验和 ----------

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func putBe16(b []byte, v uint16) { b[0] = byte(v >> 8); b[1] = byte(v) }

// csum 对字节流做反码累加（不归一化）
func csum(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(uint16(b[i])<<8 | uint16(b[i+1]))
	}
	if len(b)&1 == 1 {
		sum += uint32(uint16(b[len(b)-1]) << 8)
	}
	return sum
}

func csumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipChecksum(hdr []byte) uint16 {
	return csumFold(csum(hdr))
}

// pseudoSum 计算 IPv4 伪首部累加和
func pseudoSum(src, dst []byte, proto uint8, l4len int) uint32 {
	sum := csum(src) + csum(dst)
	sum += uint32(proto)
	sum += uint32(l4len)
	return sum
}

func verifyL4Checksum(p *Packet, l4 []byte) bool {
	sum := pseudoSum(p.L3[12:16], p.L3[16:20], uint8(p.Proto), len(l4))
	sum += csum(l4)
	return csumFold(sum) == 0
}

// computeL4Checksum 重算传输层校验和（要求 l4 中校验和字段已置 0）
func computeL4Checksum(p *Packet, l4 []byte) uint16 {
	sum := pseudoSum(p.L3[12:16], p.L3[16:20], uint8(p.Proto), len(l4))
	sum += csum(l4)
	return csumFold(sum)
}
