# nat-conntrack-go

纯 Go 实现的**本地网络地址转换（NAT）与连接跟踪（conntrack）**库。
报文输入与输出使用内存管道模拟，不依赖真实网卡、netfilter 或外部服务。

- 双向会话地址/端口改写（去程 SNAT、回程 DNAT），去程与回程五元组互相关联
- IPv4 报文解析、校验和验证与重算（IP / TCP / UDP / ICMP）
- 基于协议 + 五元组的连接跟踪，TCP/UDP/ICMP 状态机
- IP 分片的乱序缓存、重复识别、重组后整体处理与再分片
- 确定性端口分配、冲突检测、按协议独立端口空间与复用
- 会话空闲超时回收、容量上限、后台清扫
- 并发安全（单一 RWMutex 保护会话表与端口分配），统计快照一致
- 可区分的拒绝原因，异常报文不影响后续处理

## 快速开始

```go
cfg := natct.DefaultConfig()
cfg.PublicIP = netip.MustParseAddr("203.0.113.1") // NAT 外部地址

engine := natct.NewEngine(cfg)
defer engine.Close()

// 同步处理单个 IPv4 报文
out, dir, err := engine.Handle(rawPacket)
// dir == natct.DirOriginal（去程，已做 SNAT）或 natct.DirReply（回程，已做 DNAT）
```

内存管道方式：

```go
pipe := natct.NewPipe(engine)
in  := make(chan []byte, 16)
out := make(chan []byte, 16)
errc := make(chan natct.PipeError, 16)
go pipe.Run(in, out, errc)
// Run 在 in 关闭并冲刷完结果后关闭 out 与 errc
```

## 报文处理链路

```
原始字节
  └─ parsePacket        IPv4 头 / 五元组 / 校验和验证 / 分片识别
       └─ Reassembler   分片缓存、乱序重组（完整后才处理）、处理后再分片
            └─ Engine.Handle
                 ├─ Table.Lookup   去程键 / 回程键双键索引
                 ├─ Table.Create   容量检查 → 端口分配 → 建会话（任一失败不留残状态）
                 ├─ Table.Observe  协议状态机推进（非法转移拒绝且不污染状态）
                 └─ translate      地址/端口改写 + IP 与 L4 校验和重算
```

### 双向关联

每条会话保存两个五元组：

| 方向 | 改写前（Original） | 回程键（Reply） |
|------|-------------------|-----------------|
| TCP/UDP | client:sport → server:dport | server:dport → public:**mapped** |
| ICMP echo | client → server（id 在请求中） | server → public（echo reply 携带映射后的 id） |

- 去程命中 Original 键 → SNAT：源地址改为 `PublicIP`，源端口/id 改为映射端口
- 回程命中 Reply 键 → DNAT：目的地址改回内网 client，目的端口/id 改回原值

两个键指向同一会话记录，保证乱序、重复、分片报文都归入同一条会话。

## 会话状态机

### TCP

```
              SYN(去程)            SYN+ACK(回程)        ACK(去程)
  (不存在) ───────────────▶ NEW ───────────────▶ (等ACK) ───────▶ ESTABLISHED
                              │                                   │
              SYN 重传保持 NEW │                         RST ──────┤
                              │                                   │
              RST ────────────┘                          FIN ─────▼
                                                                  FIN_WAIT
                                                                     │
                                            RST / 对端FIN / 对端ACK  ▼
                                                                  CLOSED
```

- NEW 状态只接受：去程 SYN（含重传）、回程 SYN+ACK、回程/去程 RST。
- ESTABLISHED：RST → CLOSED；FIN → FIN_WAIT。
- FIN_WAIT：RST、FIN 或回程 ACK → CLOSED。
- CLOSED 是终态；任何**非法转移**返回 `ErrInvalidState`，状态保持不变（不污染）。
- 建连要求首包必须是 SYN，非 SYN 的去程 TCP 报文在分配任何资源前即被拒绝，
  因此不会残留半建立表项或占用端口。

### UDP

无连接协议，首包即创建会话（NEW）；看到回程报文后进入 ESTABLISHED。

### ICMP

仅跟踪 echo request（type 8）/ echo reply（type 0），以 ICMP identifier
作为映射"端口"。request 创建会话，reply 关联回流；其他 ICMP 类型以
`ErrProtocolUnsupported` 拒绝。

## 超时策略

超时基于每个会话的 `LastSeen`（任何**合法状态转移**的报文都会刷新；
非法报文不刷新，避免异常流量"保活"一条不应存活的会话）。

| 协议 / 状态 | 默认超时 | 说明 |
|-------------|----------|------|
| TCP NEW（仅 SYN，半建立） | 30s | 防止半开连接长期占用端口 |
| TCP ESTABLISHED | 5m | 空闲回收 |
| TCP FIN_WAIT | 10s | 快速回收关闭中的会话 |
| TCP CLOSED | 1s | 宽限后回收并释放端口 |
| UDP | 30s | |
| ICMP | 10s | |
| 分片重组缓冲 | 30s | 超时丢弃未完成的分片组 |

- `Engine` 启动后台 goroutine 每 1s 调用 `ReapExpired`；也可手动调用。
- 回收时同步删除双键索引并释放映射端口，端口可被后续会话复用。
- `MaxSessions` 为容量上限，达到后新会话返回 `ErrTableFull`，
  已有会话与后续匹配报文不受影响。

## 端口分配

- `PortAllocator` 为 TCP / UDP / ICMP 维护**各自独立**的端口空间。
- 从可配置的 `[PortMin, PortMax]` 区间内用单调游标环形扫描，
  相同操作序列产生相同结果（**结果可复现**），天然避免立即回填热点端口。
- 支持首选端口；冲突时跳过。并发分配在互斥锁内完成，保证唯一。
- 端口池耗尽返回 `ErrNoPortsAvailable`；会话回收时端口归还。
- 建会话采用"先校验、再分配、最后落表"的顺序：容量不足或端口耗尽时
  不会产生半建立状态；进程重启即全新状态，无持久化残留。

## 分片处理

- 以 `(源IP, 目的IP, 协议, IP-ID)` 作为重组键。
- 按片偏移排序，要求严格连续、无重叠（重叠视为 `ErrMalformedPacket`）。
- 同偏移重复分片：内容一致则忽略；内容不一致则拒绝（防止重叠注入污染）。
- 只在**全部到齐**后才重组并交给 NAT 处理，因此五元组提取、状态机推进、
  校验和验证都基于完整报文，分片不会产生错配。
- 处理完成后按原始分片布局再切分输出，地址改写同步到每个分片的 IP 头，
  并重算每片的 IP 头校验和。
- MF=1 的首片不做单片 L4 校验（L4 校验和覆盖整个原始报文），
  统一在重组后校验。

## 拒绝原因（可区分）

| 错误 | 触发场景 |
|------|----------|
| `ErrMalformedPacket` | 长度/头字段非法、分片重叠或冲突 |
| `ErrChecksumInvalid` | IP/TCP/UDP/ICMP 校验和不匹配 |
| `ErrProtocolUnsupported` | 非 TCP/UDP/ICMP，或不支持的 ICMP 类型 |
| `ErrInvalidState` | TCP 非法状态转移、非 SYN 建连 |
| `ErrTableFull` | 会话数达到 `MaxSessions` |
| `ErrNoPortsAvailable` | 端口池耗尽 |
| `ErrNoSession` | 回程/孤立报文找不到所属会话 |

拒绝只影响当前报文，通过独立错误通道返回，后续报文照常处理。

## 可观测性

`Table.Stats()` 返回加锁下的一致快照：

```go
type Stats struct {
    ActiveSessions int            // 未关闭会话数
    TotalCreated   uint64
    TotalPackets   uint64         // 成功处理（匹配或建连）的报文数
    Rejected       map[string]int // 按拒绝原因分类计数
}
```

计数全部在会话表互斥锁内更新，高并发下与会话实际状态保持一致。

## 测试

```
go test -race ./...
```

覆盖：UDP/TCP/ICMP 双向改写与回流、TCP 完整握手/重传/RST/FIN 与非法转移、
分片乱序/重复/冲突/缺失/超时、空闲回收与活跃保活、容量上限、
端口唯一/确定性/复用/耗尽、坏校验和/非法协议/畸形报文隔离、
以及 300 对会话的高并发双向流量压力测试。

## 范围与限制

- 仅 IPv4；不处理 IPv6。
- NAT 模型为出站 SNAT（PAT），不实现入站静态目的 NAT 规则配置。
- UDP 为简化的单方向状态模型；不实现 UDP_TWO_WAY / 隧道等高级 conntrack 状态。
- 不做 TCP 序列号/窗口的有状态序列号改写（地址端口改写等宽，无需调整序列号）。
