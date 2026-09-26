package natct

import "testing"

func TestPipe_ChannelFlowAndErrorIsolation(t *testing.T) {
	e, done := testEngine(t, baseCfg())
	defer done()
	pipe := NewPipe(e)

	in := make(chan []byte, 4)
	out := make(chan []byte, 8)
	errs := make(chan PipeError, 4)
	go pipe.Run(in, out, errs)

	client, server := ip4("10.6.0.1"), ip4("198.51.100.50")
	in <- udpPacket(client, server, 40000, 53, []byte("a"))
	in <- []byte{0x45, 0x00} // 畸形：进入错误通道，不中断
	in <- udpPacket(client, server, 40001, 53, []byte("b"))
	close(in)

	gotOut := 0
	gotErr := 0
	var outCh <-chan []byte = out
	var errCh <-chan PipeError = errs
	for outCh != nil || errCh != nil {
		select {
		case f, ok := <-outCh:
			if !ok {
				outCh = nil
				continue
			}
			if _, err := parsePacket(f); err != nil {
				t.Fatalf("output fragment invalid: %v", err)
			}
			gotOut++
		case pe, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if pe.Err != ErrMalformedPacket {
				t.Fatalf("unexpected err: %v", pe.Err)
			}
			gotErr++
		}
	}
	if gotOut != 2 {
		t.Fatalf("want 2 outputs, got %d", gotOut)
	}
	if gotErr != 1 {
		t.Fatalf("want 1 error, got %d", gotErr)
	}
}
