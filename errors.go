package natct

import "errors"

// 可区分的拒绝原因
var (
	ErrChecksumInvalid     = errors.New("natct: invalid checksum")
	ErrProtocolUnsupported = errors.New("natct: protocol unsupported")
	ErrInvalidState        = errors.New("natct: invalid state transition")
	ErrTableFull           = errors.New("natct: session table full")
	ErrNoPortsAvailable    = errors.New("natct: no ports available")
	ErrMalformedPacket     = errors.New("natct: malformed packet")
	ErrNoSession           = errors.New("natct: no matching session")
)
