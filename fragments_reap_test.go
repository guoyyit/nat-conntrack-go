package natct

import (
	"testing"
	"time"
)

func TestFragments_ReapStale(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	r := NewReassembler(e)
	base := time.Unix(2000, 0)
	r.now = func() time.Time { return base }

	client, server := ip4("10.4.0.7"), ip4("198.51.100.37")
	full := udpPacket(client, server, 40009, 53, make([]byte, 40))
	frags := splitFragments(full, 16)
	if _, err := r.Process(frags[0]); err != nil {
		t.Fatal(err)
	} // 不完整
	if r.Reap() != 0 {
		t.Fatal("fresh partial group should not reap")
	}
	r.now = func() time.Time { return base.Add(31 * time.Second) }
	if r.Reap() != 1 {
		t.Fatal("stale partial group should reap")
	}
	if e.table.Len() != 0 {
		t.Fatal("incomplete fragments must not create session")
	}
}
