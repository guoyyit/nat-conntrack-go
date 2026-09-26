// Package packet 提供 IPv4/TCP/UDP/ICMP 报文的解析、修改与序列化能力。
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// 报文解析与校验相关的可区分错误。
var (
	ErrMalformed       = errors.New("packet: malformed packet")
	ErrChecksumInvalid = errors.New("packet: checksum invalid")
	ErrNotIPv4         = errors.New("packet: not an IPv4 packet")
)

// Protocol 表示 IP 上层协议号。
type Protocol uint8

const (
	ProtocolICMP Protocol = 1
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
)

// String 返回协议的可读名称。
func (p Protocol) String() string {
	switch p {
	case ProtocolICMP:
		return "ICMP"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO(%d)", uint8(p))
	}
}

// TCP 标志位。
const (
	TCPFIN uint8 = 0x01
	TCPSYN uint8 = 0x02
	TCPRST uint8 = 0x04
	TCPACK uint8 = 0x10
)

// IP 分片标志位。
const (
	flagMF uint8 = 1 << 0 // more fragments
	flagDF uint8 = 1 << 1 // don't fragment
)

// Packet 表示一个已解析的 IPv4 报文（含传输层首部视图）。
// 修改 SrcAddr/DstAddr/SrcPort/DstPort 后调用 Serialize 得到改写后的字节流，
// 校验和会被自动修正（IP 首部全量重算，传输层按 RFC 1624 增量更新，
// 因而对仅含首片的分片报文同样正确）。
type Packet struct {
	SrcAddr  netip.Addr
	DstAddr  netip.Addr
	Protocol Protocol
	SrcPort  uint16
	DstPort  uint16
	TTL      uint8
	ID       uint16
	Flags    uint8  // DF/MF 标志（3bit）
	FragOff  uint16 // 分片偏移（单位 8 字节）
	ICMPType uint8
	ICMPCode uint8
	TCPFlags uint8
	Payload  []byte // 传输层负载（仅当传输层首部在本报文中时有效）

	origSrcAddr netip.Addr
	origDstAddr netip.Addr
	origSrcPort uint16
	origDstPort uint16

	raw          []byte
	headerLen    int
	transportOff int // 传输层首部在 raw 中的偏移；-1 表示本报文不含传输层首部
}

// IsFragment 报告报文是否为分片（含首片）。
func (p *Packet) IsFragment() bool {
	return p.FragOff != 0 || p.Flags&flagMF != 0
}

// IsFirstFragment 报告报文是否携带传输层首部（未分片或首个分片）。
func (p *Packet) IsFirstFragment() bool {
	return p.FragOff == 0
}

// Parse 解析一个 IPv4 报文字节流，并验证 IP 首部与传输层校验和。
func Parse(data []byte) (*Packet, error) {
	if len(data) < 20 {
		return nil, ErrMalformed
	}
	if data[0]>>4 != 4 {
		return nil, ErrNotIPv4
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, ErrMalformed
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen < ihl || totalLen > len(data) {
		return nil, ErrMalformed
	}
	raw := data[:totalLen]

	if Checksum(raw[:ihl]) != 0 {
		return nil, ErrChecksumInvalid
	}

	src, _ := netip.AddrFromSlice(raw[12:16])
	dst, _ := netip.AddrFromSlice(raw[16:20])
	fragField := binary.BigEndian.Uint16(raw[6:8])

	p := &Packet{
		SrcAddr:      src,
		DstAddr:      dst,
		Protocol:     Protocol(raw[9]),
		TTL:          raw[8],
		ID:           binary.BigEndian.Uint16(raw[4:6]),
		Flags:        uint8(fragField >> 13),
		FragOff:      fragField & 0x1fff,
		raw:          raw,
		headerLen:    ihl,
		transportOff: -1,
	}
	p.origSrcAddr, p.origDstAddr = src, dst

	// 非首片没有传输层首部，直接返回。
	if p.FragOff != 0 {
		return p, nil
	}

	switch p.Protocol {
	case ProtocolTCP:
		if err := p.parseTCP(); err != nil {
			return nil, err
		}
	case ProtocolUDP:
		if err := p.parseUDP(); err != nil {
			return nil, err
		}
	case ProtocolICMP:
		if err := p.parseICMP(); err != nil {
			return nil, err
		}
	default:
		// 未知协议：仅保留 IP 首部视图，由上层决定是否支持。
		p.Payload = raw[ihl:]
	}
	return p, nil
}

func (p *Packet) parseTCP() error {
	off := p.headerLen
	if len(p.raw) < off+20 {
		return ErrMalformed
	}
	p.transportOff = off
	p.SrcPort = binary.BigEndian.Uint16(p.raw[off : off+2])
	p.DstPort = binary.BigEndian.Uint16(p.raw[off+2 : off+4])
	p.TCPFlags = p.raw[off+13]
	dataOff := int(p.raw[off+12]>>4) * 4
	if dataOff < 20 || len(p.raw) < off+dataOff {
		return ErrMalformed
	}
	p.Payload = p.raw[off+dataOff:]
	// 分片报文的传输层校验和覆盖重组后的完整数据报，首片无法独立验证。
	if !p.IsFragment() && transportChecksum(p.raw[:p.headerLen], p.raw[off:]) != 0 {
		return ErrChecksumInvalid
	}
	p.origSrcPort, p.origDstPort = p.SrcPort, p.DstPort
	return nil
}

func (p *Packet) parseUDP() error {
	off := p.headerLen
	if len(p.raw) < off+8 {
		return ErrMalformed
	}
	p.transportOff = off
	p.SrcPort = binary.BigEndian.Uint16(p.raw[off : off+2])
	p.DstPort = binary.BigEndian.Uint16(p.raw[off+2 : off+4])
	p.Payload = p.raw[off+8:]
	csum := binary.BigEndian.Uint16(p.raw[off+6 : off+8])
	// UDP 校验和为 0 表示未启用（IPv4 允许）；分片首片无法独立验证。
	if csum != 0 && !p.IsFragment() && transportChecksum(p.raw[:p.headerLen], p.raw[off:]) != 0 {
		return ErrChecksumInvalid
	}
	p.origSrcPort, p.origDstPort = p.SrcPort, p.DstPort
	return nil
}

func (p *Packet) parseICMP() error {
	off := p.headerLen
	if len(p.raw) < off+4 {
		return ErrMalformed
	}
	p.transportOff = off
	p.ICMPType = p.raw[off]
	p.ICMPCode = p.raw[off+1]
	// 对 echo 请求/应答，用 identifier 充当“端口”以支持五元组跟踪。
	if p.ICMPType == 0 || p.ICMPType == 8 {
		if len(p.raw) < off+8 {
			return ErrMalformed
		}
		id := binary.BigEndian.Uint16(p.raw[off+4 : off+6])
		p.SrcPort, p.DstPort = id, id
		p.origSrcPort, p.origDstPort = id, id
	}
	p.Payload = p.raw[off+4:]
	if !p.IsFragment() && Checksum(p.raw[off:]) != 0 {
		return ErrChecksumInvalid
	}
	return nil
}

// transportChecksum 计算 TCP/UDP 校验和（含伪首部）。
func transportChecksum(ipHeader, segment []byte) uint16 {
	pseudo := make([]byte, 0, 12+len(segment))
	pseudo = append(pseudo, ipHeader[12:20]...) // 源/目的地址
	pseudo = append(pseudo, 0, ipHeader[9])
	pseudo = append(pseudo, byte(len(segment)>>8), byte(len(segment)))
	pseudo = append(pseudo, segment...)
	return Checksum(pseudo)
}

// Serialize 将修改后的报文重新序列化并修正校验和。
func (p *Packet) Serialize() ([]byte, error) {
	out := make([]byte, len(p.raw))
	copy(out, p.raw)

	src := p.SrcAddr.As4()
	dst := p.DstAddr.As4()
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])

	// IP 首部校验和全量重算。
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], Checksum(out[:p.headerLen]))

	// 传输层校验和按 RFC 1624 增量更新（仅当本报文携带传输层首部）。
	if p.transportOff >= 0 {
		switch p.Protocol {
		case ProtocolTCP, ProtocolUDP:
			binary.BigEndian.PutUint16(out[p.transportOff:p.transportOff+2], p.SrcPort)
			binary.BigEndian.PutUint16(out[p.transportOff+2:p.transportOff+4], p.DstPort)
			csumOff := p.transportOff + 16 // TCP
			if p.Protocol == ProtocolUDP {
				csumOff = p.transportOff + 6
			}
			old := binary.BigEndian.Uint16(out[csumOff : csumOff+2])
			if p.Protocol == ProtocolTCP || old != 0 {
				oldWords := addrWords(p.origSrcAddr, p.origDstAddr)
				oldWords = append(oldWords, p.origSrcPort, p.origDstPort)
				newWords := addrWords(p.SrcAddr, p.DstAddr)
				newWords = append(newWords, p.SrcPort, p.DstPort)
				csum := UpdateTransportChecksum(wordsToBytes(oldWords), wordsToBytes(newWords), old)
				// UDP 计算结果为 0 时须写为 0xffff（0 表示未启用）。
				if p.Protocol == ProtocolUDP && csum == 0 {
					csum = 0xffff
				}
				binary.BigEndian.PutUint16(out[csumOff:csumOff+2], csum)
			}
		case ProtocolICMP:
			// ICMP 校验和不覆盖 IP 地址；echo 的 identifier 未改动时无需更新。
			if p.SrcPort != p.origSrcPort {
				csumOff := p.transportOff + 2
				old := binary.BigEndian.Uint16(out[csumOff : csumOff+2])
				csum := UpdateTransportChecksum(
					wordsToBytes([]uint16{p.origSrcPort}),
					wordsToBytes([]uint16{p.SrcPort}), old)
				binary.BigEndian.PutUint16(out[csumOff:csumOff+2], csum)
				binary.BigEndian.PutUint16(out[p.transportOff+4:p.transportOff+6], p.SrcPort)
			}
		}
	}
	return out, nil
}

func addrWords(addrs ...netip.Addr) []uint16 {
	var words []uint16
	for _, a := range addrs {
		b := a.As4()
		words = append(words, binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4]))
	}
	return words
}

func wordsToBytes(words []uint16) []byte {
	b := make([]byte, 0, len(words)*2)
	for _, w := range words {
		b = append(b, byte(w>>8), byte(w))
	}
	return b
}
