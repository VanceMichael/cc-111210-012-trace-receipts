# 脱敏抓包格式与关联提取

本地文件为小端 PCAPNG，含两个以太网接口、IPv4/TCP 包，以及微秒和纳秒两种时间分辨率选项。`/trace.pcapng` 返回字节；包内容仅为 192.0.2.0/24 与 gateway.test 的合成请求。演练包未计算链路校验和，采集语义不依赖网卡卸载状态。

EPB 中的 TCP 有效负载包含两个流水线 GET、一次 100 Continue 及两次最终响应，前向包乱序并有同字节重传。查看器验证 PCAPNG 块长度并读取以太网、IPv4 与 TCP 头；`/extract` 在其上增加按 TCP 序列号的字节流装配和 HTTP/1.1 请求/回执关联。

## 提取规则

- **接口与时间**：每个接口按自己的 `if_tsresol`（十进制或二进制）与 `if_tsoffset` 换算成纳秒后再排序。文件顺序相同的包保持稳定次序。
- **连接世代**：同一四元组上的新 SYN（不含 ACK）开启新世代；SYN 重传按初始序列号识别。无 SYN 的包先按 ACK/序列号区间归属，缺少序列号证据时按观察时间贴近度选择，绝不无条件归到最新世代。
- **装配**：两个方向分别按序列号合并。重复字节只入账一次；重叠内容冲突终止该方向装配并保留先到/被拒字节；缺口未补齐时不越过缺口拼接。半途开始或缺口之后的不可解析前缀会按行边界重新同步，跳过的字节单独留证。
- **缓存**：上限按连接共享。达到上限时终止该方向并给出原因（`cache-limit`），已装配字节保留，不丢旧字节后继续。
- **HTTP 边界**：请求按 `Content-Length` / chunked；响应按状态码、请求方法（HEAD）、1xx/204/304、`Content-Length`、chunked 或关闭定界判定。关闭定界只有见到 FIN 才判完整，RST 或抓包结束都记为截断。
- **配对**：请求按流中顺序排队，响应按同一顺序配对；1xx 作为中间响应挂到紧随其后的最终响应上。没有最终回执、只有中间响应、响应早于请求或无法解析的片段都明确列为无主/截断，不伪造结果。

## 证据回溯

每条请求、中间响应和最终响应都带 `evidence` 数组，逐段给出：

- `interfaceId`：包所在接口；
- `packetNumber`：按文件顺序的全局包号（跨接口唯一）；
- `fileOffset`：PCAPNG 文件内字节区间；
- `frameOffset`：以太网帧内字节区间（从帧首字节起算）；
- `sequence` / `streamRange`：TCP 序列号与装配流内区间；
- `timestamp`：该段所属包的观察时间（纳秒）。

顶层 `ledger` 给出每条请求的简明账目（方法、目标、最终状态、`reply` 分类、请求/回执包号），便于实施同事直接筛选“是否收到回复”。`summary` 与 `ledger` 中的 `reply` 取值：`complete`、`truncated`、以及 `request-incomplete`、`response-missing`、`final-missing`、`precedes-request`、`request-missing`、`unparsable-prefix`、`head-incomplete`、`malformed-head`、`body-truncated`、`capture-ended`、`connection-reset` 等无法形成完整回执的状态。

顶层 `fragments` 汇总所有不能成为完整回执的片段：`sequence-gap`、`overlap-conflict`、`unassembled-segment`、`unattached-message`、`incomplete-message`、`stream-termination`、`truncated-frame`、`skipped-frame`。`summary` 给出完整、截断、缺失与无主的计数。

## 演练场景

`fixtures/scenarios.mjs` 生成以下本地合成流量（不访问网络）：

| 场景 | 覆盖点 |
| --- | --- |
| `baseline` | 乱序、重传、流水线、100 Continue、chunked、关闭定界、双接口时间分辨率 |
| `requestGap` | 请求方向缺口，不拼出看似完整的请求 |
| `overlapConflict` | 同序列号不同字节，终止装配并留证 |
| `midstreamStart` | 无 SYN 半途开始，不可解析前缀重新同步 |
| `connectionReuse` | 同四元组新 SYN 重建，两代回执不串 |
| `interleavedTimestamps` | 文件顺序与时间戳不一致时按观察时间归属 |
| `cacheLimit` | 缓存达到上限的终止原因 |
| `truncatedBody` | Content-Length 不足，标为截断 |
| `closeDelimitedWithFin` / `closeDelimitedNoFin` | FIN 判定完整与抓包结束截断 |
| `pipelinedPosts` | POST 正文与流水线切分 |
| `reversedSegments` | 完全逆序到达的向前并入 |
| `interimOnly` | 只有 100 Continue，最终回执缺失 |
| `multiInterface` | 同一连接跨接口的证据回溯 |

来源服务还提供 `/trace/<场景>.pcapng`，可用 `SOURCE_URL` 指向已启动的本地来源后访问 `/extract`。
