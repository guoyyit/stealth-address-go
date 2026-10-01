# stealth-address-go

一次性收款地址（stealth address）服务的 Go 实现：发送方为已注册接收方生成
不可关联的一次性地址，输出以本地只追加日志持久化；接收方用只读视图（扫描）
密钥发现属于自己的输出，再用花费密钥恢复一次性私钥。

仅依赖 Go 标准库，曲线为 NIST P-256。

## 密钥模型

每个接收方持有一个长期 `MasterKey`（高熵随机标量，**永不上传服务**）。对每个
身份字符串 `receiverID`，确定性派生两个互相独立的密钥：

- **扫描/视图密钥 `v`（ScanPriv）**，公钥 `V = v*G`。只读，可分发给扫描进程；
  能发现输出归属，但**不能花费**，也不能恢复一次性私钥。
- **花费密钥 `b`（SpendPriv）**，公钥 `B = b*G`。敏感，仅接收方持有。

派生使用带域分离标签的 SHA-256：

```
v = H_scan(master || receiverID)   (mod N)
b = H_spend(master || receiverID) (mod N)
```

同一 master 与同一 ID 永远派生出同一密钥对；不同 ID 派生结果以压倒性概率不同。
注册时服务只保存 `{V, B}`，不保存任何私钥。

## 地址协议（双密钥 stealth address）

```
发送方（输入 V, B）:
  r  <- 随机标量（每次地址生成全新、独立）
  R  = r*G                      临时公钥
  h  = H_out(R, r*V)            共享点 r*V = v*R（ECDH）
  P  = B + h*G                  一次性公钥
输出记录公开 (R, P)。

接收方扫描（持有 v）:
  h = H_out(R, v*R)
  P == B + h*G  ⇒ 输出属于本接收方

接收方花费（持有 v, b）:
  p = b + h (mod N), 满足 p*G = P
```

### 安全边界

- **不可关联性**：每个地址使用独立随机 `r`，`R` 与 `P` 在 CDH/随机预言机模型
  下与 `(V, B)` 计算不可区分，同一接收方的多个一次性地址之间也没有可计算关联。
  输出流中看不到接收方身份公钥。
- **视图密钥不赋予花费能力**：扫描只做比较（`matchOutput`），不计算一次性私钥；
  `p = b + h` 必须有花费标量 `b`。仅持有 `v` 的一方恢复私钥会得到
  `ErrSpendKeyMismatch`（当其提交任意非注册花费公钥）或无法通过认证。
- **非接收方**：错误视图密钥扫描得到 `ErrViewKeyMismatch`；他人输出恢复得到
  `ErrNotOwner`。
- **哈希与点编码**：所有派生经 SHA-256 域分离；点以 33 字节压缩 SEC1 传输，
  解析时强制曲线方程校验，拒绝非点点。

本实现不提供：网络传输层、金额/元数据加密（`Meta` 明文落盘）、针对恶意注册者
占用他人 ID 的命名空间治理、以及量子安全。

## 存储布局（目录 `Config.Dir`）

```
outputs.log       只追加输出日志（帧见下），每条 append 后 fsync
outputs.meta      8B：清理边界 retainedFirst（原子 temp+rename+fsync）
registry.json     接收方 {ID -> V,B} 全量快照，原子 temp+rename+fsync
scans/<id>.cursor 每接收方扫描游标：魔数 + 8B 游标，原子写入
```

日志帧格式：

```
0x53 0x4f | 4B 大端载荷长度 | JSON 载荷（含 seq,id,R,P,amount,meta）| 4B CRC32
```

序列 `seq` 单调递增、**永不复用**（清理后也如此），并保存在帧内。

### 崩溃恢复

- 打开日志时全量重放、重建内存索引；任何**部分写入或 CRC 错误的尾部帧被
  截断**并 fsync，调用方永远观察不到半条记录。
- 注册表与游标均为「临时文件 → fsync → rename → fsync 目录」的原子替换，
  崩溃只可能留下旧版本，不可能出现半写内容。
- 输出在返回 `SubmitOutput` 成功前已 fsync；崩溃前已确认的输出重开后必然存在。
- 扫描游标在结果返回前原子提交，崩溃恢复后：
  - 已提交区间**不会重复报告**；
  - 崩溃前已持久化但尚未扫描到的输出在下次 `Scan` 中**不会遗漏**；
  - 极小窗口（游标已提交、结果尚未返回时崩溃）：该区间不会再被报告。若需要
    权威重建，调用方可显式执行 `Rescan` 并按输出 ID 自行去重。

## 扫描与并发语义

- `Scan(id, viewKey)` 从该接收方已提交游标增量扫描到当前流前沿，按 `seq`
  升序返回匹配输出，并在同一接收方粒度上加锁串行化：同一接收方的并发扫描
  不会重复报告，也不会丢失；不同接收方互不阻塞。
- 游标只允许单调前进（`commit` 拒绝回退）。
- 输出按 ID 去重；重复到达的同一 ID 为幂等重投（`SubmitOutput` 返回
  `ErrOutputExists`，不产生第二条记录），扫描绝不会重复报告同一 ID。
- 输入乱序不影响匹配（匹配只依赖记录内的 `(R,P)`），报告顺序固定为流序。
- `Register` / `Unregister` 与进行中的扫描互不破坏：撤销时等待该接收方扫描
  临界区结束后再删除游标；已开始的扫描使用其捕获的密钥集完成。

## 清理与重新扫描

- `Prune(beforeSeq)` 用「重写保留段 → fsync → rename」原子删除 `seq <
  beforeSeq` 的输出，并推进 `outputs.meta` 中的清理边界。
- 若某接收方**已初始化**的游标落在清理边界之前，后续增量 `Scan` 立即返回
  `ErrPrunedData`，**绝不静默跳过**历史；新接收方（游标为 0）从当前边界开始，
  不算丢失进度。
- 已清理输出的 `Recover` 返回 `ErrOutputNotFound`（无法访问其元数据，显式
  报错而不是静默返回错误密钥）。
- `Rescan(id, viewKey)` 的确定语义：**重扫整个仍然保留的区间**（从
  `retainedFirst` 到前沿），重新报告其中全部属于该接收方的输出，并把游标重置
  到前沿。它是「权威快照」，不是「新增通知」：调用方必须按输出 ID 合并/替换，
  被清理的输出不会重新出现。

## 可区分的错误

| 错误 | 场景 |
| --- | --- |
| `ErrReceiverNotFound` | 接收方未注册（或已撤销） |
| `ErrReceiverExists` | 重复注册同一 ID |
| `ErrInvalidArgument` | 空 ID / nil 密钥 / 非法标量 |
| `ErrInvalidAddress` | 点编码非法、不在曲线上 |
| `ErrViewKeyMismatch` | 视图密钥与注册扫描公钥不一致 |
| `ErrSpendKeyMismatch` | 花费密钥与注册花费公钥不一致 |
| `ErrNotOwner` | 输出不属于该接收方 |
| `ErrOutputNotFound` | ID 不存在或已被清理 |
| `ErrOutputExists` | 同一 ID 重复提交（幂等拒绝） |
| `ErrPrunedData` | 已提交游标指向已清理区间，需 `Rescan` |
| `ErrCorruptStorage` | 日志/游标/注册表不可恢复损坏 |

## 使用示例

```go
svc, _ := stealth.Open(stealth.Config{Dir: "./data"})
defer svc.Close()

mk, _ := stealth.GenerateMasterKey()
kp, _ := stealth.DeriveKeyPair(mk, "alice")
_ = svc.RegisterReceiver("alice", kp)

addr, _ := svc.GenerateAddress("alice")
_ = svc.SubmitOutput(stealth.OutputRecord{
    ID: []byte("payment-1"), EphemeralPub: addr.EphemeralPub,
    OneTimePub: addr.OneTimePub, Amount: 1000,
})

// 扫描进程只需视图密钥
report, _ := svc.Scan("alice", kp.ScanPriv)

// 花费时才使用完整密钥
priv, err := svc.Recover("alice", []byte("payment-1"), kp)
```

## 测试

```
go test -race ./...
```

覆盖：确定性派生、地址间/跨身份不可关联性、乱序与重复提交、增量扫描幂等、
崩溃重开状态恢复、日志半写截断与魔数损坏、游标原子性、同/异接收方并发扫描、
并发注册/撤销、清理边界显式报错、重新扫描确定性、错误视图/花费密钥与非属主恢复。
