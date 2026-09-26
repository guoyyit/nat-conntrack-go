// Package testutil 提供测试中构造 IPv4/TCP/UDP/ICMP 报文的工具函数。
package testutil

import (
	"encoding/binary"
	"net/netip"

	"github.com/guoyyit/nat-conntrack-go/packet"
)

// BuildIPv4 构造一个 IPv4 首部（含正确校验和），payload 为上层报文。
func BuildIPv4(src, dst netip.Addr, proto uint8, id uint16, payload []byte) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(hdr[4:6], id)
	hdr[8] = 64
	hdr[9] = proto
	s := src.As4()
	d := dst.As4()
	copy(hdr[12:16], s[:])
	copy(hdr[16:20], d[:])
	binary.BigEndian.PutUint16(hdr[10:12], packet.Checksum(hdr))
	return append(hdr, payload...)
}

// BuildTCP 构造一个 TCP 报文（校验和正确）。
func BuildTCP(src, dst netip.Addr, sport, dport uint16, flags uint8, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	seg[12] = 5 << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:], payload)
	ip := BuildIPv4(src, dst, 6, 1, seg)
	fixTransportChecksum(ip)
	return ip
}

// BuildUDP 构造一个 UDP 报文（校验和正确）。
func BuildUDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	seg := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
	copy(seg[8:], payload)
	ip := BuildIPv4(src, dst, 17, 1, seg)
	fixTransportChecksum(ip)
	return ip
}

// BuildICMPEcho 构造一个 ICMP echo 报文（校验和正确）。
func BuildICMPEcho(src, dst netip.Addr, id uint16, reply bool, payload []byte) []byte {
	msg := make([]byte, 8+len(payload))
	if reply {
		msg[0] = 0
	} else {
		msg[0] = 8
	}
	binary.BigEndian.PutUint16(msg[4:6], id)
	copy(msg[8:], payload)
	binary.BigEndian.PutUint16(msg[2:4], packet.Checksum(msg))
	return BuildIPv4(src, dst, 1, 1, msg)
}

// fixTransportChecksum 计算并填充 TCP/UDP 校验和（含伪首部）。
func fixTransportChecksum(ip []byte) {
	ihl := int(ip[0]&0x0f) * 4
	seg := ip[ihl:]
	var csumOff int
	switch ip[9] {
	case 6:
		csumOff = 16
	case 17:
		csumOff = 6
	default:
		return
	}
	binary.BigEndian.PutUint16(seg[csumOff:csumOff+2], 0)
	pseudo := make([]byte, 0, 12+len(seg))
	pseudo = append(pseudo, ip[12:20]...)
	pseudo = append(pseudo, 0, ip[9])
	pseudo = append(pseudo, byte(len(seg)>>8), byte(len(seg)))
	pseudo = append(pseudo, seg...)
	csum := packet.Checksum(pseudo)
	if ip[9] == 17 && csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(seg[csumOff:csumOff+2], csum)
}

// Fragment 将一个 IP 报文按 fragPayloadSize 字节切片分片，
// 返回分片序列（除末片外均带 MF 标志，偏移与校验和正确）。
func Fragment(ip []byte, fragPayloadSize int) [][]byte {
	ihl := int(ip[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	payload := ip[ihl:total]
	// 分片负载须为 8 的倍数（末片除外）。
	fragPayloadSize &^= 7
	if fragPayloadSize < 8 {
		fragPayloadSize = 8
	}
	var frags [][]byte
	for off := 0; off < len(payload); off += fragPayloadSize {
		end := off + fragPayloadSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		frag := make([]byte, ihl+len(chunk))
		copy(frag[:ihl], ip[:ihl])
		copy(frag[ihl:], chunk)
		binary.BigEndian.PutUint16(frag[2:4], uint16(ihl+len(chunk)))
		fragField := uint16(off / 8)
		if end < len(payload) {
			fragField |= 1 << 13 // MF
		}
		binary.BigEndian.PutUint16(frag[6:8], fragField)
		binary.BigEndian.PutUint16(frag[10:12], 0)
		binary.BigEndian.PutUint16(frag[10:12], packet.Checksum(frag[:ihl]))
		frags = append(frags, frag)
	}
	return frags
}

// Addr 由点分十进制字符串构造 netip.Addr。
func Addr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}
