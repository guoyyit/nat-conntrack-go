package packet

import "encoding/binary"

// Checksum 计算数据的互联网校验和（RFC 1071）。
func Checksum(data []byte) uint16 {
	sum := checksumSum(data)
	return ^sum
}

// checksumSum 计算数据的 16 位反码和（未取反）。
func checksumSum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// csumAdd 将若干 16 位字以反码加法并入校验和。
func csumAdd(csum uint16, words ...uint16) uint16 {
	sum := uint32(^csum)
	for _, w := range words {
		sum += uint32(w)
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// csumSub 从校验和中以反码减法移除若干 16 位字。
func csumSub(csum uint16, words ...uint16) uint16 {
	sum := uint32(^csum)
	for _, w := range words {
		sum += uint32(^w)
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// UpdateTransportChecksum 在地址或端口改写后增量更新传输层校验和：
// 从校验和中减去 old 中的各 16 位字，再加上 new 中的各 16 位字。
func UpdateTransportChecksum(old, new []byte, csum uint16) uint16 {
	ow := bytesToWords(old)
	nw := bytesToWords(new)
	csum = csumSub(csum, ow...)
	return csumAdd(csum, nw...)
}

// bytesToWords 将字节切片按大端序拆成 16 位字序列。
func bytesToWords(b []byte) []uint16 {
	words := make([]uint16, 0, (len(b)+1)/2)
	for len(b) >= 2 {
		words = append(words, binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		words = append(words, uint16(b[0])<<8)
	}
	return words
}
