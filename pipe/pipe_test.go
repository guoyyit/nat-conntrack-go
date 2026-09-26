package pipe_test

import (
	"sync"
	"testing"

	"github.com/guoyyit/nat-conntrack-go/pipe"
)

func TestSendRecvFIFO(t *testing.T) {
	p := pipe.New(4)
	if !p.Send([]byte("a")) || !p.Send([]byte("b")) {
		t.Fatal("Send failed")
	}
	if p.Len() != 2 {
		t.Fatalf("Len = %d, want 2", p.Len())
	}
	got, ok := p.Recv()
	if !ok || string(got) != "a" {
		t.Fatalf("Recv = %q, %v", got, ok)
	}
	got, ok = p.Recv()
	if !ok || string(got) != "b" {
		t.Fatalf("Recv = %q, %v", got, ok)
	}
	if _, ok := p.Recv(); ok {
		t.Fatal("empty pipe should report !ok")
	}
}

func TestSendFullAndClosed(t *testing.T) {
	p := pipe.New(1)
	if !p.Send([]byte("x")) {
		t.Fatal("first Send failed")
	}
	if p.Send([]byte("y")) {
		t.Fatal("Send to full pipe should fail")
	}
	p.Close()
	if p.Send([]byte("z")) {
		t.Fatal("Send to closed pipe should fail")
	}
	if p.Len() != 0 {
		t.Fatal("Close must drop queued packets")
	}
}

func TestConcurrent(t *testing.T) {
	p := pipe.New(1024)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				p.Send([]byte{byte(i)})
			}
		}()
	}
	wg.Wait()
	n := 0
	for {
		if _, ok := p.Recv(); !ok {
			break
		}
		n++
	}
	if n != 400 {
		t.Fatalf("received %d, want 400", n)
	}
}
