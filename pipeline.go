package natct

import "time"

// PipeError 携带被拒绝报文的可区分原因，不中断后续处理
type PipeError struct {
	Err error
}

func (e PipeError) Error() string { return e.Err.Error() }
func (e PipeError) Unwrap() error { return e.Err }

// Pipe 是本地内存双向报文管道：不依赖真实网卡。
type Pipe struct {
	engine *Engine
	reasm  *Reassembler
}

func NewPipe(e *Engine) *Pipe {
	return &Pipe{engine: e, reasm: NewReassembler(e)}
}

// Run 从 inCh 读取报文，改写后的全部分片写入 outCh；
// 单个报文失败只把原因写入 errCh，后续报文继续处理。
// 入站关闭并冲刷完所有结果后，Run 会关闭 outCh 与 errCh——
// 因此每组通道只能由一个 Run 消费，且由 Run 负责关闭。
func (p *Pipe) Run(inCh <-chan []byte, outCh chan<- []byte, errCh chan<- PipeError) {
	reap := time.NewTicker(10 * time.Second)
	defer func() {
		reap.Stop()
		close(outCh)
		close(errCh)
	}()
	for {
		select {
		case raw, ok := <-inCh:
			if !ok {
				return
			}
			p.feed(raw, outCh, errCh)
		case <-reap.C:
			p.reasm.Reap()
		}
	}
}

// Process 同步处理一个报文，便于直接调用
func (p *Pipe) Process(raw []byte) ([][]byte, error) {
	return p.reasm.Process(raw)
}

func (p *Pipe) feed(raw []byte, outCh chan<- []byte, errCh chan<- PipeError) {
	defer func() {
		if r := recover(); r != nil {
			errCh <- PipeError{Err: ErrMalformedPacket}
		}
	}()
	frags, err := p.reasm.Process(raw)
	if err != nil {
		errCh <- PipeError{Err: err}
		return
	}
	for _, f := range frags {
		outCh <- f
	}
}
