# HTTP/3 frame 解包与打包设计

Status: proposed

> 2026-09-08：对齐新版 [ChunkBody 与 owner 契约](../../dhttp/design/public-api/exchange/README.md#5-上传使用-asyncwrite接收使用-body)。本篇是实现契约及流程伪码，尚未编译或执行验收；先落地 wire，后接入 owner/ChunkBody 与 QPACK 调度。原生任务样例不代表已经支持 wasm。

### 当前落地范围（2026-09-08）

帧解析首批实现已采用私有 ChunkReader/FrameReader：qbase VarInt 复用，header/payload 两阶段，DATA 至多 16 KiB 切分，未知 payload 流式丢弃，64 KiB 单帧及 8 MiB 连接聚合预算，保留 payload 到 QPACK 解码结束。请求、响应、control 和 WT 分类调用者已迁移；收到错误先保持原始 code/source 和范围，response 取消后不再允许从半帧重试，GOAWAY 覆盖 payload 等待。

本批直接基于 chunk 读取 VarInt 和受限 payload，没有增加 AsyncRead/io::Error 适配；下文 AsyncRead 片段保留为方案说明，不是已落地依赖。接收仍沿用现有私有 Body/try_unfold，未实现新版公共 ChunkBody/owner。分块发送、QPACK 定向唤醒及 1 MiB blocked 子预算、消息 policy/默认解压字段限额、wasm 验收仍按后续步骤执行，不能从帧解析完成推断这些工作已完成。

已通过默认和 all-features 的单元、集成及文档测试；新增边界包括 Pending、半帧 EOF/reset/transport failure、预算释放、未知帧、取消、GOAWAY 和 control 错误范围。fuzz 入口已经调用实际 FrameReader，确定性 smoke 用例通过；当前环境未安装 cargo-fuzz，尚未进行持续 fuzz。

## 1. 目标

重构 `h3x::wire` 的 HTTP/3 frame 读写路径：

- 使用 `qbase::varint::{be_varint, VarInt, WriteVarInt}`，不在 h3x 内复制 VarInt 实现。
- 结构化、已知长度的非 DATA payload 聚合后使用 `nom` 解析。
- DATA payload 直接按 transport `Bytes` chunk 流式交付，不聚合整帧。
- 打包时分别发送 frame header 和 payload，不再将 DATA 复制到一个连续缓冲区。
- 未知 frame 按声明长度流式丢弃，不为未知 payload 分配等长内存。
- QPACK field section 因 Required Insert Count 阻塞时，只唤醒已满足条件的 stream，不在每次插入后唤醒全部等待者。
- 同时限制单个 HEADERS payload 和整个 connection 上被 blocked field section 保留的总字节数。
- 保留 transport connection error 和 stream reset 的原有语义；仅 clean EOF 造成的半帧映射为 `H3_FRAME_ERROR`。

## 2. 非目标

- 不重建旧版通用 `DecodeFrom` / `EncodeInto` codec 框架。
- 不为四种当前使用的 HTTP/3 frame 建立泛型 factory 或 trait 树。
- 不改变 `transport::{RecvStream, SendStream}` 公共 SPI。
- 第一版不将 QPACK parser 重写为逐字段增量状态机；HEADERS payload 仍是受限 `Bytes`，但 blocked stream 改为定向唤醒。
- 不在 `dhttp` 内重复实现 frame codec；该能力属于 `h3x`。

## 3. 从 qbase 借用的模式

qbase 的 frame 路径可概括为：

1. `be_frame_type` 先解析 VarInt type。
2. `complete_frame` 按 type 选择对应的 nom parser。
3. parser 返回消费长度和 `Frame` 枚举。
4. `FrameReader` 在成功后 advance 已消费的 `Bytes`。
5. 打包通过 `BufMut + WriteVarInt` 顺序写入字段。

HTTP/3 不能照搬 qbase 的 `Iterator<Bytes>`：QUIC packet payload 已在内存中且大小受 packet 边界约束，HTTP/3 frame 则位于可长期存在的 QUIC stream 上，一个 DATA frame 可以跨越任意多个 transport chunk。

因此保留 qbase 的“先 type，再按 type 解析”，但将读取分成两层：

```text
transport::RecvStream<Item = Result<Bytes, StreamError>>
                         |
                         v
                    ChunkReader
          AsyncRead + zero-copy read_chunk
                         |
                         v
                    FrameReader
            Type + Length + remaining
               /          |          \
              v           v           v
           DATA       known frame    unknown frame
        read_chunk()  bounded Bytes   discard()
                         |
                         v
                    nom / QPACK
```

## 4. 数据类型

```rust
const DATA: u64 = 0x00;
const HEADERS: u64 = 0x01;
const CANCEL_PUSH: u64 = 0x03;
const SETTINGS: u64 = 0x04;
const PUSH_PROMISE: u64 = 0x05;
const GOAWAY: u64 = 0x07;
const MAX_PUSH_ID: u64 = 0x0d;

enum FrameType {
    Data,
    Headers,
    Settings,
    Goaway,

    // h3x 当前不支持 server push，但不能将这些已知类型
    // 当成可忽略的未知扩展。
    CancelPush,
    PushPromise,
    MaxPushId,

    // HTTP/2 中已定义但在 HTTP/3 中保留且禁止发送的类型。
    ForbiddenHttp2,

    // 真正的未知扩展。
    Unknown(VarInt),
}

struct FrameHeader {
    frame_type: FrameType,
    length: u64,
}

fn classify_frame_type(value: VarInt) -> FrameType {
    match value.into_u64() {
        DATA => FrameType::Data,
        HEADERS => FrameType::Headers,
        CANCEL_PUSH => FrameType::CancelPush,
        SETTINGS => FrameType::Settings,
        PUSH_PROMISE => FrameType::PushPromise,
        GOAWAY => FrameType::Goaway,
        MAX_PUSH_ID => FrameType::MaxPushId,
        0x02 | 0x06 | 0x08 | 0x09 => FrameType::ForbiddenHttp2,
        _ => FrameType::Unknown(value),
    }
}
```

## 5. ChunkReader：transport chunk 到字节流

以下算法片段省略第 8.1 节统一的协作让出计数和第 8.2 节调用层预算 guard；实现及测试必须同时落实这两个前置条件，不能将省略理解为无限循环/无限分配许可。

`ChunkReader` 对应前期设计中的私有 `Reader`。名称强调它只负责 transport chunk，不理解 HTTP/3 frame。

```rust
struct ChunkReader {
    stream: Box<dyn transport::RecvStream>,
    pending: Bytes,
    ended: bool,
}

impl ChunkReader {
    // 取出不超过 max 字节。返回值直接 slice transport Bytes，
    // DATA 路径不经过 ReadBuf，因此不复制 payload。
    fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Poll<Result<Option<Bytes>, transport::StreamError>> {
        assert!(max > 0);

        loop {
            if !self.pending.is_empty() {
                let len = self.pending.len().min(max);
                return Ready(Ok(Some(self.pending.split_to(len))));
            }

            if self.ended {
                return Ready(Ok(None));
            }

            match Pin::new(&mut *self.stream).poll_next(cx) {
                Pending => return Pending,
                Ready(Some(Ok(bytes))) if bytes.is_empty() => continue,
                Ready(Some(Ok(bytes))) => self.pending = bytes,
                Ready(Some(Err(error))) => {
                    self.ended = true;
                    return Ready(Err(error));
                }
                Ready(None) => {
                    self.ended = true;
                    return Ready(Ok(None));
                }
            }
        }
    }

    async fn read_chunk(
        &mut self,
        max: usize,
    ) -> Result<Option<Bytes>, transport::StreamError> {
        poll_fn(|cx| self.poll_chunk(cx, max)).await
    }

    fn stop(&mut self, code: Code) -> Result<(), Error> {
        self.stream.stop(code).map_err(map_stream_error)
    }
}

impl AsyncRead for ChunkReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Ready(Ok(()));
        }

        match ready!(self.get_mut().poll_chunk(cx, output.remaining())) {
            Ok(Some(bytes)) => {
                // 这条路径用于 VarInt 和受限的结构化 payload。
                output.put_slice(&bytes);
                Ready(Ok(()))
            }
            Ok(None) => Ready(Ok(())),
            Err(error) => Ready(Err(io::Error::other(error))),
        }
    }
}
```

## 6. 异步 VarInt

`be_varint` 仍是唯一的 VarInt 解析器。异步层只负责根据首字节补齐 1/2/4/8 字节。

```rust
async fn read_varint_opt(reader: &mut ChunkReader) -> Result<Option<VarInt>, Error> {
    let mut encoded = [0u8; VarInt::MAX_SIZE];

    let read = reader
        .read(&mut encoded[..1])
        .await
        .map_err(map_reader_error)?;

    // 只有在两个 frame 之间才允许 clean EOF。
    if read == 0 {
        return Ok(None);
    }

    let encoded_len = 1usize << (encoded[0] >> 6);

    reader
        .read_exact(&mut encoded[1..encoded_len])
        .await
        .map_err(|error| {
            map_incomplete_frame_error(error, "incomplete QUIC varint")
        })?;

    let (_, value) = be_varint(&encoded[..encoded_len])
        .map_err(|error| h3_frame_error(format!("invalid QUIC varint: {error:?}")))?;

    Ok(Some(value))
}

async fn read_varint(reader: &mut ChunkReader) -> Result<VarInt, Error> {
    read_varint_opt(reader)
        .await?
        .ok_or_else(|| h3_frame_error("missing QUIC varint"))
}
```

## 7. 双向流分类：不在 FrameReader 内保存 first_type

WebTransport 双向流和 HTTP request stream 共享 QUIC 双向流空间，所以必须消费第一个 VarInt 才能分类。这个“已读取但未处理”的状态无法消失，但不应以 `first_type: Option<VarInt>` 隐藏在通用 `FrameReader` 内。

分类器直接返回领域枚举：

```rust
enum ClassifiedBidi {
    Http {
        // 分类时已经读完的第一个 HTTP frame header。
        first: FrameHeader,
        frames: FrameReader,
    },
    WebTransport {
        session_id: StreamId,
        reader: ChunkReader,
    },
}

async fn classify_bidi(mut reader: ChunkReader) -> Result<ClassifiedBidi, Error> {
    let first = read_varint(&mut reader).await?;

    if first.into_u64() == WEBTRANSPORT_BIDI_SIGNAL {
        let session_id = stream_id::try_from_u64(
            read_varint(&mut reader).await?.into_u64(),
        )?;

        return Ok(ClassifiedBidi::WebTransport {
            session_id,
            reader,
        });
    }

    // HTTP frame header 的第二个 VarInt 是 payload length。
    let length = read_varint(&mut reader).await?.into_u64();
    let first = FrameHeader {
        frame_type: classify_frame_type(first),
        length,
    };

    Ok(ClassifiedBidi::Http {
        first,
        // 第一个 header 已被读取，FrameReader 从其 payload 开始。
        frames: FrameReader::after_header(reader, length),
    })
}
```

这样：

- `FrameReader` 不知道 WebTransport signal。
- 不需要 peek/unread 或回放原始字节。
- 已消费的首 header 是 `Http` 分支的显式输出，不是 reader 内的特例缓存。
- 分类完成后，HTTP 和 WebTransport 路径拥有各自正确的 reader 状态。

未选择的方案：

- `peek_varint + unread` 需要新增前置缓冲和回放逻辑。
- `tokio::io::BufReader` 可能预读 DATA，使零复制 chunk 路径更难保持。
- 将 WT signal 伪装成 HTTP frame type 会把 session ID 错当成 payload length。

## 8. FrameReader

```rust
struct FrameReader {
    input: ChunkReader,
    // 当前 frame 尚未消费的 payload 长度。
    remaining: u64,
}

impl FrameReader {
    fn new(input: ChunkReader) -> Self {
        Self {
            input,
            remaining: 0,
        }
    }

    fn after_header(input: ChunkReader, length: u64) -> Self {
        Self {
            input,
            remaining: length,
        }
    }

    async fn next_header(&mut self) -> Result<Option<FrameHeader>, Error> {
        // 当前 payload 必须先读完或丢弃。
        assert_eq!(self.remaining, 0);

        let Some(frame_type) = read_varint_opt(&mut self.input).await? else {
            return Ok(None);
        };

        let length = read_varint(&mut self.input).await?.into_u64();
        self.remaining = length;

        Ok(Some(FrameHeader {
            frame_type: classify_frame_type(frame_type),
            length,
        }))
    }

    async fn read_payload(&mut self, limit: usize) -> Result<Bytes, Error> {
        let len = usize::try_from(self.remaining)
            .map_err(|_| h3_excessive_load("frame payload does not fit in memory"))?;

        if len > limit {
            return Err(h3_excessive_load(
                "buffered frame payload exceeds implementation limit",
            ));
        }

        let mut payload = BytesMut::zeroed(len);

        self.input
            .read_exact(&mut payload)
            .await
            .map_err(|error| {
                map_incomplete_frame_error(error, "incomplete HTTP/3 frame payload")
            })?;

        self.remaining = 0;
        Ok(payload.freeze())
    }

    // 读取当前 frame payload 的一个零复制 chunk。
    // DATA 直接交付返回值；未知 frame 读取后直接 drop。
    async fn read_payload_chunk(&mut self, chunk_limit: usize) -> Result<Option<Bytes>, Error> {
        assert!(chunk_limit > 0);
        if self.remaining == 0 {
            return Ok(None);
        }

        let max = usize::try_from(self.remaining).unwrap_or(usize::MAX).min(chunk_limit);

        match self.input.read_chunk(max).await {
            Ok(Some(bytes)) => {
                self.remaining -= bytes.len() as u64;
                Ok(Some(bytes))
            }
            Ok(None) => Err(h3_frame_error(
                "stream ended in the middle of an HTTP/3 frame payload",
            )),
            Err(error) => Err(map_stream_error(error)),
        }
    }

    async fn discard_payload(&mut self) -> Result<(), Error> {
        while self.remaining != 0 {
            // 与 DATA 使用相同的 chunk 切分，但直接 drop。
            self.read_payload_chunk(16 * 1024).await?;
        }
        Ok(())
    }

    fn stop(&mut self, code: Code) -> Result<(), Error> {
        self.input.stop(code)
    }
}
```

### 8.1 Pending、取消与错误后的状态

`next_header`、`read_payload`、异步 VarInt 和分类器不是可取消后重试的读取事务。半个 VarInt、已读 header 或聚合偏移保存在进行中的 future 中：Pending 后必须继续 poll 同一个 future。`select!` 中若其他分支胜出但还要继续读取，必须在循环外 pin 并保留该 future；禁止丢弃后重新创建。`FrameReader` 私有，不向应用承诺这种重试能力。

首版复用当前 `try_unfold` 保存读取 future，或在 owner 的顺序 async 循环中直接 await。停止接收时允许丢弃整个读取 future 和 reader，由方向 guard 提交 STOP_SENDING、取消 QPACK 等待并清理；不能在这条流上继续猜测下一帧。发送半帧被取消同样由现有 RequestSendCommit/ResetOnDrop reset，禁止重发 header。普通 Pending 不等于取消。

transport reset/connection failure 先恢复原始 code/source；只有 clean EOF 截断 envelope/payload 才是 H3_FRAME_ERROR。错误后该读取器退出，不再把下一次读取的 None 当作成功。连接级错误必须先调用现有 fail_connection 广播并关闭连接，再处理 Body 错误入队，不能被满队列阻塞。关键流关闭的映射由 control/QPACK 层负责。

连续空 chunk、零长度 DATA 或未知帧也需要公平性：一次连续处理至多 64 个无应用输出的步骤，然后协作让出并安排唤醒；恢复时保留原 future。未知 payload 每次丢弃至多 16 KiB，不聚合、不限制整条消息总长度。不能让一个始终 Ready 的业务流饿死 control/QPACK。

### 8.2 首版资源契约

以下为首版实现取值，均在本地可信配置中决定，不由 peer SETTINGS 上调；新增的是私有限额，不新增公共配置框架。

| 资源 | 首版界限 | 取得与释放 |
|---|---|---|
| 单个压缩 HEADERS（含 trailers、1xx） | 64 KiB，`MAX_BUFFERED_FRAME_PAYLOAD` | 检查声明长度后、分配前预留 |
| 单个 SETTINGS | 64 KiB | 同一聚合上限；解析时不重复保存原始条目 |
| 每连接聚合 payload 总量 | 8 MiB，`MAX_BUFFERED_PAYLOAD_BYTES` | 包含正在读取、等待 QPACK、已唤醒未解码的 payload；RAII guard 持有到原始 Bytes 释放 |
| 上述总量中曾进入 QPACK blocked 的 payload | 1 MiB，`MAX_BLOCKED_FIELD_SECTION_BYTES` | 注册时额外计费，唤醒不释放，解码完成/取消时释放；是总量的子集 |
| 单个解压 field section | 默认 32 KiB（name + value + 每字段 32 字节） | 解码过程中检查；已解压 HeaderMap/排队 trailers 另按字段预算计量 |
| DATA 块 | owner 给定 C，至多 16 KiB | `read_payload_chunk(C)` 切分；4 个排队块 + 1 个在途块遵守交换文档 W |
| GOAWAY / push ID payload | 至多 8 字节且恰好一个 VarInt | 固定小缓冲，不进入大 payload 聚合 |

`read_payload` 的调用前置条件是调用层已经持有对应 length 的连接预算 guard；该 guard 与 payload 同生命周期，不能在函数返回 Bytes 时就释放。申请使用 checked arithmetic，超额立即返回 connection H3_EXCESSIVE_LOAD，不排队等预算，避免依赖关键流推进才能释放预算的等待环。错误、半帧、取消和失败广播都必须释放 guard。

HEADERS 上限限制压缩字节，字段上限限制解压结果；二者不能互相替代。解压字符串/Huffman 时须在增长输出前检查剩余字段额度，不能先分配完整膨胀结果再判超限。初始首部、1xx、trailers 使用同一限制，忽略的 1xx 解码后立即释放，不累计保存。排队 trailers 不占 DATA 的 W：每方向至多一份，按字段限额和已准入交换数量保守核算；显式上调字段限额须同步调整独立头部预算。

零复制指不为 DATA 制作整帧副本。`Bytes::slice/split_to` 可能保留大底层分配：transport 必须在切片仍存活时继续将其计入自己的接收内存预算；无法兑现的适配器应交付有界独立 chunk。h3x 自己新增的分配不得以切片长度低估；必要时按 C 复制。上述数值不能被宣传为进程 RSS 上限。

## 9. 核心调用逻辑

1. connection accept loop 在有界准入后登记每条 stream 的工作；未读完首部、QPACK blocked 和等待应用接管也占并发名额。
2. resolver 解析初始首部，将私有 ReceivedBody 交给同一个 owner 的接收工作；应用只得到三成员 ChunkBody。
3. owner 增量读取并投递 `Result<Option<Frame<Bytes>>, Error>`；最多保留一个未入队块，队列满就停止该业务流的读取。

wire 不创建公共 BodyWriter、ChunkBody 或 Pool。首个 wire 提交可暂时沿用当前私有 `try_unfold`/Body 适配；这只是迁移桥梁，最终驱动者是 owner，不长期保留第二套公共接收 Body。原生 JoinSet 示例省略的准入、退出 guard 和 abort 后 join 必须复用交换运行层，不能把裸 spawn 当作最终契约；wasm 按 transport 文档使用本地根 future。

### 9.1 双向流 accept loop

```rust
async fn accept_bidi_streams<T: transport::Connection>(
    connection: Arc<T>,
    requests: mpsc::Sender<AcceptedRequest>,
) -> Result<(), Error> {
    let mut stream_tasks = JoinSet::new();

    loop {
        tokio::select! {
            accepted = connection.accept_bi() => {
                let (recv, send) = accepted.map_err(map_connection_error)?;
                let stream_id = validate_stream_pair(&recv, &send)?;
                let requests = requests.clone();

                stream_tasks.spawn(async move {
                    let reader = ChunkReader::new(Box::new(recv));

                    #[cfg(feature = "webtransport")]
                    match classify_bidi(reader).await? {
                        ClassifiedBidi::Http { first, frames } => {
                            resolve_http_stream(
                                Some(first),
                                frames,
                                Box::new(send),
                                stream_id,
                                requests,
                            )
                            .await
                        }
                        ClassifiedBidi::WebTransport { session_id, reader } => {
                            route_webtransport_bidi(
                                session_id,
                                reader,
                                Box::new(send),
                            )
                            .await
                        }
                    }

                    #[cfg(not(feature = "webtransport"))]
                    resolve_http_stream(
                        None,
                        FrameReader::new(reader),
                        Box::new(send),
                        stream_id,
                        requests,
                    )
                    .await
                });
            }

            completed = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) if error.is_connection() => {
                        return Err(error);
                    }
                    Some(Ok(Err(_stream_error))) => {
                        // 单条 request stream 失败，其他 stream 继续。
                    }
                    Some(Err(join_error)) => {
                        return Err(h3_internal_error(join_error));
                    }
                    None => {}
                }
            }

            error = connection.closed() => {
                return Err(map_connection_error(error));
            }
        }
    }
}
```

accept loop 只管生命周期和并发，不解析 frame。每条流的 parser 状态都属于它自己的 task。

### 9.2 单条 HTTP stream resolver

```text
resolve_http_stream(first, frames, send, stream_id)：
    在交换登记/预算 guard 下 await read_initial_headers
    校验请求消息语义，生成标准 request parts
    构造私有 ReceivedBody(frames, qpack, stream_id, body_policy, C)
    在 owner 登记接收方向工作，创建 frames/stop/ended 的 ChunkBody
    向应用交付 Request<ChunkBody> 与现有响应发送能力
    交付失败：停止该接收方向，收回未逃逸的发送能力和登记

owner 接收工作：
    await 同一个 ReceivedBody.next_body_frame future
    DATA/trailers → await frames.send(Ok(Some(frame)))，之后才读下一块
    验证 FIN → await frames.send(Ok(None))，之后不再读流
    失败 → 先传播连接级错误，再尝试入队 Err(error)，之后不再生产
    终态入队后等待 receiver.closed；消费者读到终态或 Drop 才收尾
    消费者停止/队列关闭 → 放弃待投递项，STOP_SENDING（若尚未正常结束）
    所有路径 → QPACK 取消/预算释放，交回外层监督回收
```

读取、等待队列空间和等待 receiver.closed 都必须可被方向停止/连接退出唤醒；取消后丢弃整个读取工作，不能重启半帧读取。队列仅携带结果，ChunkBody 不持有协议 reader、预算 guard 或共享完成槽。正常 EOF/error 是最后一个队列项；队列意外断开由 ChunkBody 报 OwnerStopped。

### 9.3 单向流核心分派

```rust
async fn handle_uni_stream(mut reader: ChunkReader) -> Result<(), Error> {
    let stream_type = read_varint(&mut reader).await?.into_u64();

    match stream_type {
        CONTROL_STREAM_TYPE => {
            claim_unique_peer_control_stream()?;
            handle_control_stream(FrameReader::new(reader)).await
        }
        QPACK_ENCODER_STREAM_TYPE => {
            claim_unique_peer_qpack_encoder_stream()?;
            // QPACK instruction stream 不使用 HTTP/3 frame envelope。
            qpack.handle_encoder_stream(reader).await
        }
        QPACK_DECODER_STREAM_TYPE => {
            claim_unique_peer_qpack_decoder_stream()?;
            qpack.handle_decoder_stream(reader).await
        }
        PUSH_STREAM_TYPE => {
            reject_push_stream_for_peer_role()
        }
        WEBTRANSPORT_UNI_STREAM_TYPE => {
            let session_id = stream_id::try_from_u64(
                read_varint(&mut reader).await?.into_u64(),
            )?;
            route_webtransport_uni(session_id, reader)
        }
        _unknown => {
            // 未知单向流类型必须读取丢弃或停止读取。
            drain_to_end(reader).await
        }
    }
}
```

### 9.4 完整接收调用链

```text
accept_bidi_streams
  -> ChunkReader::new
  -> classify_bidi                         [WebTransport feature]
  -> resolve_http_stream
       -> read_initial_headers             [初始 frame 循环]
            -> FrameReader::next_header
            -> FrameReader::discard_payload [unknown]
            -> FrameReader::read_payload    [HEADERS]
            -> qpack.decode_request/response
                 -> Decoder::decode_or_block
                      -> Ready
                      `-> Blocked { oneshot::Receiver }
                           ^
                           |
QPACK encoder stream -> apply_encoder_instruction
                           -> 只唤醒 required <= insert_count 的 stream
       -> owner 持有 ReceivedBody { frames, ... }
            -> 有界队列生产循环
                 -> ReceivedBody::next_body_frame [body 循环]
                      -> FrameReader::read_payload_chunk [DATA]
                      -> FrameReader::next_header
                      -> FrameReader::read_payload       [trailers]
                      -> FrameReader::discard_payload    [unknown]
            -> frames.send(DATA/trailers/EOF/error)
                 -> ChunkBody::poll_frame 只读队列
```

## 10. 非 DATA payload parser

### 10.1 SETTINGS

nom 只负责字节结构；重复 identifier、HTTP/2 保留 identifier 和布尔值范围等语义验证仍显式处理，以保留正确的 HTTP/3 error code。

```rust
fn parse_settings(mut input: &[u8]) -> Result<Settings, Error> {
    let mut settings = Settings::default();
    let mut seen = BTreeSet::new();

    while !input.is_empty() {
        let (remaining, (identifier, value)) = (be_varint, be_varint)
            .parse(input)
            .map_err(|error| {
                h3_frame_error(format!("malformed SETTINGS payload: {error:?}"))
            })?;

        input = remaining;
        let identifier = identifier.into_u64();
        let value = value.into_u64();

        if !seen.insert(identifier) {
            return Err(h3_settings_error("duplicate setting identifier"));
        }

        if matches!(identifier, 0x02 | 0x03 | 0x04 | 0x05) {
            return Err(h3_settings_error(
                "HTTP/2 setting identifier used in HTTP/3",
            ));
        }

        match identifier {
            QPACK_MAX_TABLE_CAPACITY => {
                settings.set_qpack_max_table_capacity(value);
            }
            MAX_FIELD_SECTION_SIZE => {
                settings.set_max_field_section_size(Some(value));
            }
            QPACK_BLOCKED_STREAMS => {
                settings.set_qpack_blocked_streams(value);
            }
            ENABLE_CONNECT_PROTOCOL => match value {
                0 => settings.set_enable_connect_protocol(false),
                1 => settings.set_enable_connect_protocol(true),
                _ => {
                    return Err(h3_settings_error(
                        "SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1",
                    ));
                }
            },
            _ => {
                // 未知 setting 必须忽略。
            }
        }
    }

    Ok(settings)
}
```

### 10.2 GOAWAY

```rust
fn parse_goaway(input: &[u8]) -> Result<VarInt, Error> {
    let (_, value) = all_consuming(be_varint)
        .parse(input)
        .map_err(|error| h3_frame_error(format!("malformed GOAWAY payload: {error:?}")))?;
    Ok(value)
}
```

### 10.3 HEADERS

HEADERS frame envelope 由 `FrameReader` 处理；payload 聚合成受限 `Bytes` 后交给 QPACK：

```rust
let encoded_fields = frames
    .read_payload(MAX_BUFFERED_FRAME_PAYLOAD)
    .await?;

let parts = qpack.decode_request(stream_id, &encoded_fields).await?;
```

QPACK 有自己的可变长整数、Huffman 和动态表状态，不为了“统一用 nom”在本次重写。

### 10.4 QPACK blocked field section：定向唤醒与预算生命周期

第一版保留受限完整 HEADERS，不重写增量 QPACK parser。prefix 只解析一次；保存绝对 Required Insert Count、Base、field-lines 起始偏移。RIC 表示历史插入总数，不是某个表项 ID；线上 Encoded Insert Count 按当前总插入数和动态表最大容量还原，唤醒后不得用更新后的总插入数重新还原。依据 [RFC 9204 §4.5.1.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1)。

```text
field-section future 持有：
    encoded Bytes + 聚合预算 guard
    首次解析的 prefix { required_insert_count, base, fields_offset }
    可选 blocked 预算 guard + 注册取消 guard

decoder 持有：
    table + max_blocked_streams
    blocked: BTreeMap<StreamId, { required_insert_count, oneshot sender }>

首次读取 prefix（在 decoder mutex 下）：
    已失败 → 原始 failure
    RIC <= insert_count → 用保存的 prefix 解码 fields
    RIC > insert_count → 检查 blocked stream 数与字节子预算
        同一把锁下注册唯一 stream entry，取得取消 guard 与 oneshot receiver
        await receiver 或 connection failure
        唤醒后 → 用已保存 prefix 解码 fields，不再 decode_or_block

encoder insertion（在同一 decoder mutex 下）：
    更新 table，取出所有 required <= insert_count 的 entry
    解除这些 stream 的 blocked 数量登记；不释放 payload 字节预算
    锁外发送相应 oneshot；其他 stream 不唤醒

完成/错误/取消：
    注册 guard 移除尚存 entry（已唤醒则为空操作）
    原始 payload 释放时归还聚合预算及曾取得的 blocked 子预算
```

表插入后先收集需要唤醒的 sender，再离开锁；任何后续指令入队失败必须发布 connection failure，不能静默丢掉 sender。保留现有 failure 存储和终止广播路径；waiter 先订阅失败通知，再检查 failure 并注册。oneshot 被关闭时先检查原始 failure，有则原样返回；无则返回内部错误，不能把真实 QPACK/transport 失败改成唤醒器错误。

解码时仍校验索引、最大引用与 RIC 的一致性。RIC 已满足但表项已淘汰/索引非法，返回 QPACK_DECOMPRESSION_FAILED，不能等待未来插入。每个 stream 顺序处理初始 HEADERS、各个 1xx/final 和 trailers，同一时刻最多一个 field-section future。成功引用动态表后按现有路径发送 SectionAcknowledgement；读取方向被放弃时复用 cancel_stream/StreamCancellation，不能重复确认同一 section。

注册与检查必须原子化；同步注册完成后、离开该调用前就装入取消 guard，不能留一次 await 的泄漏窗口。取消 stream 只移除 registry，不替仍存活的 future 释放内存计费；connection failure 同样广播、停止生产，再由各 future 析构释放预算。外层监督等待清理完成。

`SETTINGS_QPACK_BLOCKED_STREAMS` 只统计尚未满足 RIC 的 stream；blocked 字节子预算为了约束实际保留内存，继续覆盖已唤醒未解码的 section。这两个计数有意使用不同释放时机。

`ponytail: 首版按有界 blocked map 做 O(n) 扫描；只有 profiling 证明 insertion 扫描成为瓶颈才增加 RIC 二级索引。`

完整 payload 聚合、blocked 保留和解压分别使用第 8.2 节限制。不声称 blocked payload 仍占 transport flow-control window；当前 chunk SPI 的信用释放行为由适配器决定，严格按需求读取的 SPI 和增量 QPACK 属于后续独立工作。

## 11. Control stream 读取

```rust
async fn handle_control_stream(mut frames: FrameReader) -> Result<(), Error> {
    let first = frames
        .next_header()
        .await?
        .ok_or_else(|| h3_closed_critical_stream(
            "control stream ended before SETTINGS",
        ))?;

    // 首个未知 frame 也不能跳过，它没有满足“首帧是 SETTINGS”。
    if !matches!(first.frame_type, FrameType::Settings) {
        return Err(h3_missing_settings());
    }

    let payload = frames
        .read_payload(MAX_BUFFERED_FRAME_PAYLOAD)
        .await?;
    let settings = parse_settings(&payload)?;
    apply_peer_settings(settings).await?;

    while let Some(header) = frames.next_header().await? {
        match header.frame_type {
            FrameType::Goaway => {
                if header.length > VarInt::MAX_SIZE as u64 {
                    return Err(h3_frame_error(
                        "GOAWAY payload is longer than one QUIC varint",
                    ));
                }
                let payload = frames
                    .read_payload(VarInt::MAX_SIZE)
                    .await?;
                apply_peer_goaway(parse_goaway(&payload)?)?; // profile/发起者校验在此处
            }
            FrameType::Settings => {
                return Err(h3_frame_unexpected("second SETTINGS frame"));
            }
            FrameType::Unknown(_) => {
                frames.discard_payload().await?;
            }
            FrameType::ForbiddenHttp2
            | FrameType::Data
            | FrameType::Headers
            | FrameType::PushPromise => {
                return Err(h3_frame_unexpected(
                    "frame is forbidden on control stream",
                ));
            }
            FrameType::CancelPush | FrameType::MaxPushId => {
                // bounded single-VarInt parser；语义按第 11.1 节。
                handle_push_control(header, &mut frames).await?;
            }
        }
    }

    Err(h3_closed_critical_stream("control stream closed"))
}
```

### 11.1 profile、push 与 WebTransport

frame parser 只解析 GOAWAY 的单个 VarInt，不把它先验地转换成 StreamId。h3x 当前是 [已约定的对称 profile](../README.md)：两端 GOAWAY 都表示不再接受对端发起的请求流边界。`apply_peer_goaway` 验证收到的 ID 是本端发起的双向流、后续边界不增大，并使 ID >= boundary 的请求走现有拒绝/重试路径；不要求该 ID 已经实际开流。本轮不改变此 profile，也不自动声称它等同标准单向 client/server HTTP/3。标准 HTTP/3 server GOAWAY 为 client bidi stream ID，client GOAWAY 为 push ID，若另加标准模式，应在连接语义层选择，不能在 codec 猜测。[RFC 9114 §7.2.6](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.6)

首版不发送 MAX_PUSH_ID/PUSH_PROMISE/push stream。push 已知帧不可归入 Unknown；按语义而非“不支持”统一报错：

| 入站情况 | 裁决 |
|---|---|
| PUSH_PROMISE 在 control 或请求方向 | H3_FRAME_UNEXPECTED |
| PUSH_PROMISE 在响应方向 | 读取有界 push ID 前缀；本端未授权任何 push ID，H3_ID_ERROR，不分配 QPACK section |
| CANCEL_PUSH 在 control | payload 恰好一个 VarInt；本端未承诺或获准任何 push，H3_ID_ERROR |
| MAX_PUSH_ID 在 control | 对称 profile 可接收对端对本端 push 的授权；验证单 VarInt、单调不减，记录最大值但不主动 push |
| CANCEL_PUSH/MAX_PUSH_ID 在请求或响应流 | H3_FRAME_UNEXPECTED |
| push 单向流 | QUIC server 收到 client push stream 为 H3_STREAM_CREATION_ERROR；QUIC client 未授权 push 时为 H3_ID_ERROR |

长度/VarInt 截断仍是 H3_FRAME_ERROR；上述位置错误先于 payload 聚合检查。标准角色下 MAX_PUSH_ID 只能由 client 发送；对称 profile 的双向授权解释须作为扩展行为记录在互联测试中。[RFC 9114 §7.2.3–7.2.7](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.3)

保留现有 WebTransport SETTINGS（H3_DATAGRAM、WT_ENABLED）的编解码和布尔值验证，不能因第 10/13 节样例省略而删掉；stream 分类后仍执行现有会话/协商校验。WT signal 只在双向流起点有分类意义，在已分类 HTTP 流中按现有 WT 协议路径拒绝，不能误读 session ID 为 length。关闭 feature 时不启用 WT 路由。

## 12. Request/response stream 读取

### 12.1 消息状态与长度

请求方向为 `initial HEADERS → DATA* → trailers? → FIN`；响应方向为 `合法 1xx HEADERS* → final HEADERS → DATA* → trailers? → FIN`。首部解析完成后才交付 Request/Response；101 非法，1xx 不交付为最终 Response。final 后的 HEADERS 只允许作为 trailers 解码，出现 :status 等伪首部为 H3_MESSAGE_ERROR；第二份 trailers 或 trailers 后 DATA 为 H3_FRAME_UNEXPECTED。真正未知帧可穿插，包括 trailers 后；必须丢弃完并验证最终 FIN，trailers 不提前代表 EOF。

connection 层保存本次请求 method 和最终 status，计算私有 body policy 后交给读取/发送循环；wire 不知道 method。下面的 ReceivedBody 伪码展示普通有内容路径，`content_length_remaining` 不是所有响应共用的唯一状态。

| 消息 | 内容/长度契约 |
|---|---|
| 普通可有内容请求/响应 | Content-Length 缺省允许读到 FIN；存在则逐 DATA 声明长度扣减，超额立即报错，trailers/FIN 前必须归零 |
| HEAD 响应、304 | Content-Length 可描述假设内容长度，不能据此等 DATA；首部之后不得进入内容/trailers 路径 |
| 1xx、204 | 不发送 Content-Length；接收出现该字段按非法消息拒绝；不接受内容；1xx 后继续等待 final |
| 普通 CONNECT 2xx | 不套 Content-Length 倒计数；发送禁止 Content-Length，接收忽略该字段，交给隧道路径；未实现普通隧道交接前不能作为普通 Body 成功交付 |
| WebTransport CONNECT | 保留既有扩展的协商、首部和会话交接规则，不套普通响应 Body policy |
| TRACE 请求 | 不接受请求内容，开流前校验本地 Fixed 内容 |

无内容 final 响应在 HEADERS 后只丢弃允许的未知扩展并等待 FIN；不能因 policy 无内容就丢弃 reader，否则无法发现非法尾随帧。出站 HEAD 响应可使用已知表示长度生成元数据，但不得发送 Body 内容；其他非法本地内容应在可发现时拒绝，不能静默当成功发送。状态/长度规则依据 [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6) 与 [RFC 9114 §4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1)。

Content-Length 只接受去除允许空白后的十进制数字串，禁止正负号、空项和溢出；重复值/逗号列表仅所有值相同才接受。trailer 禁止伪首部及 Content-Length 等影响消息定界/路由的字段。错误返回 stream H3_MESSAGE_ERROR；半个 DATA payload 的 clean EOF 仍优先为 connection H3_FRAME_ERROR。流式交付过的数据不回滚，后续错误作为唯一终态交付。

### 12.2 普通内容读取流程

WebTransport 未开启时，初始 HEADERS 解析从 `frames.next_header()` 开始。WebTransport 开启时，`ClassifiedBidi::Http` 会带入 `first`；它只是请求 resolver 的局部初始值，不保存在通用 reader 中。

```rust
async fn read_initial_headers(
    frames: &mut FrameReader,
    mut first: Option<FrameHeader>,
    stream_id: StreamId,
) -> Result<http::request::Parts, Error> {
    loop {
        let header = match first.take() {
            Some(header) => header,
            None => frames
                .next_header()
                .await?
                .ok_or_else(|| h3_request_incomplete(
                    "request stream ended before initial HEADERS",
                ))?,
        };

        match header.frame_type {
            FrameType::Headers => {
                let payload = frames
                    .read_payload(MAX_BUFFERED_FRAME_PAYLOAD)
                    .await?;
                return qpack.decode_request(stream_id, &payload).await;
            }
            FrameType::Data => {
                return Err(h3_frame_unexpected(
                    "DATA received before initial HEADERS",
                ));
            }
            FrameType::Unknown(_) => {
                frames.discard_payload().await?;
            }
            FrameType::ForbiddenHttp2
            | FrameType::Settings
            | FrameType::Goaway
            | FrameType::CancelPush
            | FrameType::PushPromise
            | FrameType::MaxPushId => {
                return Err(h3_frame_unexpected(
                    "frame is forbidden before request HEADERS",
                ));
            }
        }
    }
}

struct ReceivedBody {
    stream_id: StreamId,
    frames: FrameReader,
    chunk_limit: usize, // owner 传入 C；不是 transport chunk 大小。
    current_is_data: bool,
    trailers_received: bool,
    content_length_remaining: Option<u64>,
}

impl ReceivedBody {
    async fn next_body_frame(
        &mut self,
    ) -> Result<Option<http_body::Frame<Bytes>>, Error> {
        loop {
            // 只要当前 DATA frame 还有 payload，就不读下一个 header。
            if self.current_is_data {
                if let Some(bytes) = self.frames.read_payload_chunk(self.chunk_limit).await? {
                    return Ok(Some(http_body::Frame::data(bytes)));
                }
                self.current_is_data = false;
            }

            let Some(header) = self.frames.next_header().await? else {
                if self
                    .content_length_remaining
                    .is_some_and(|remaining| remaining != 0)
                {
                    return Err(h3_message_error("Content-Length mismatch"));
                }
                return Ok(None);
            };

            match header.frame_type {
                FrameType::Data => {
                    if self.trailers_received {
                        return Err(h3_frame_unexpected(
                            "DATA received after trailers",
                        ));
                    }

                    // 在看到 frame header 时就检查声明长度，
                    // 不必等 payload 逐 chunk 到达。
                    if let Some(remaining) = &mut self.content_length_remaining {
                        *remaining = remaining
                            .checked_sub(header.length)
                            .ok_or_else(|| {
                                h3_message_error("DATA exceeds Content-Length")
                            })?;
                    }

                    self.current_is_data = true;
                    // 零长度 DATA 在下一轮直接结束。
                }

                FrameType::Headers => {
                    if self.trailers_received {
                        return Err(h3_frame_unexpected("HEADERS after trailers"));
                    }

                    if self
                        .content_length_remaining
                        .is_some_and(|remaining| remaining != 0)
                    {
                        return Err(h3_message_error(
                            "trailers received before Content-Length was satisfied",
                        ));
                    }

                    let payload = self.frames
                        .read_payload(MAX_BUFFERED_FRAME_PAYLOAD)
                        .await?;
                    let trailers = qpack.decode_trailers(self.stream_id, &payload).await?;
                    self.trailers_received = true;
                    return Ok(Some(http_body::Frame::trailers(trailers)));
                }

                FrameType::Unknown(_) => {
                    // request stream 中的真正未知扩展可以穿插在消息中。
                    self.frames.discard_payload().await?;
                }

                FrameType::PushPromise => {
                    return reject_push_promise(self.stream_id, &mut self.frames).await;
                }
                FrameType::ForbiddenHttp2
                | FrameType::Settings
                | FrameType::Goaway
                | FrameType::CancelPush
                | FrameType::MaxPushId => {
                    return Err(h3_frame_unexpected(
                        "frame is forbidden on request stream",
                    ));
                }
            }
        }
    }
}
```

`ClassifiedBidi::Http { first, frames }` 直接调用 `read_initial_headers(&mut frames, Some(first), stream_id)`。普通 HTTP 路径传 `None`。初始 HEADERS 解析完成后才构造 `ReceivedBody`，因此 body reader 不需要再表示 `InitialHeaders` 阶段。

## 13. 打包

qbase 在受限 packet buffer 上使用 `WriteFrame` 将 header 和 data 写入同一个 `BufMut`。HTTP/3 的 transport 直接接受 `Sink<Bytes>`，因此可将 header 和 payload 作为两个 chunk 提交。Sink item 边界不是 QUIC stream 字节边界。

### 13.1 构造 payload

```rust
fn encode_settings_payload(settings: &Settings) -> Result<Bytes, Error> {
    let mut output = BytesMut::new();

    if let Some(value) = settings.encoded_qpack_max_table_capacity() {
        output.put_varint(&VarInt::from_u32(QPACK_MAX_TABLE_CAPACITY));
        output.put_varint(&VarInt::try_from(value)?);
    }

    if let Some(value) = settings.max_field_section_size() {
        output.put_varint(&VarInt::from_u32(MAX_FIELD_SECTION_SIZE));
        output.put_varint(&VarInt::try_from(value)?);
    }

    if let Some(value) = settings.encoded_qpack_blocked_streams() {
        output.put_varint(&VarInt::from_u32(QPACK_BLOCKED_STREAMS));
        output.put_varint(&VarInt::try_from(value)?);
    }

    if let Some(value) = settings.encoded_enable_connect_protocol() {
        output.put_varint(&VarInt::from_u32(ENABLE_CONNECT_PROTOCOL));
        output.put_varint(&VarInt::from_u32(value as u32));
    }

    Ok(output.freeze())
}

fn encode_goaway_payload(stream_id: StreamId) -> Bytes {
    let mut output = BytesMut::with_capacity(VarInt::MAX_SIZE);
    output.put_varint(&stream_id.into());
    output.freeze()
}
```

### 13.2 构造通用 frame header

```rust
fn encode_frame_header(
    frame_type: u64,
    payload_len: usize,
) -> Result<Bytes, Error> {
    let frame_type = VarInt::try_from(frame_type)?;
    let payload_len = VarInt::try_from(payload_len)?;

    let mut output = BytesMut::with_capacity(
        frame_type.encoding_size() + payload_len.encoding_size(),
    );

    output.put_varint(&frame_type);
    output.put_varint(&payload_len);

    Ok(output.freeze())
}
```

### 13.3 发送 frame

```rust
async fn send_frame(
    writer: &mut BoxSendStream,
    frame_type: u64,
    payload: Bytes,
) -> Result<(), Error> {
    let header = encode_frame_header(frame_type, payload.len())?;

    writer
        .feed(header)
        .await
        .map_err(map_stream_error)?;

    if !payload.is_empty() {
        // DATA 和 HEADERS 原始 Bytes 的 ownership 直接转移给 transport。
        writer
            .feed(payload)
            .await
            .map_err(map_stream_error)?;
    }

    writer.flush().await.map_err(map_stream_error)
}

async fn send_data(
    writer: &mut BoxSendStream,
    data: Bytes,
) -> Result<(), Error> {
    send_frame(writer, DATA, data).await
}

async fn send_headers(
    writer: &mut BoxSendStream,
    encoded_fields: Bytes,
) -> Result<(), Error> {
    send_frame(writer, HEADERS, encoded_fields).await
}

async fn send_settings(
    writer: &mut BoxSendStream,
    settings: &Settings,
) -> Result<(), Error> {
    send_frame(writer, SETTINGS, encode_settings_payload(settings)?).await
}

async fn send_goaway(
    writer: &mut BoxSendStream,
    boundary: StreamId,
) -> Result<(), Error> {
    send_frame(writer, GOAWAY, encode_goaway_payload(boundary)).await
}
```

### 13.4 发送消息的核心循环

```rust
async fn send_message<B>(
    mut writer: BoxSendStream,
    stream_id: StreamId,
    initial_headers: Bytes,
    chunk_limit: usize, // owner 的 C，必须 > 0。
    body: B,
    mut content_length_remaining: Option<u64>,
    qpack: &Qpack,
) -> Result<(), Error>
where
    B: http_body::Body + Send,
    B::Data: Buf + Send,
{
    // 1. 初始 HEADERS。
    send_headers(&mut writer, initial_headers).await?;

    let mut body = pin!(body);
    let mut trailers_sent = false;

    // 2. Body 主循环。一次只从上层取一个 http_body frame。
    loop {
        let Some(frame) = body.as_mut().frame().await else {
            if content_length_remaining.is_some_and(|remaining| remaining != 0) {
                return Err(h3_message_error("Content-Length mismatch"));
            }

            // 3. 正常 FIN。
            writer.close().await.map_err(map_stream_error)?;
            return Ok(());
        };

        let frame = frame.map_err(map_body_error)?;

        match frame.into_data() {
            Ok(mut data) => {
                if trailers_sent {
                    return Err(h3_message_error("body produced DATA after trailers"));
                }

                let len = data.remaining();
                if let Some(remaining) = &mut content_length_remaining {
                    *remaining = remaining
                        .checked_sub(len as u64)
                        .ok_or_else(|| {
                            h3_message_error("body exceeds Content-Length")
                        })?;
                }

                // Bytes 可零复制切分；通用 Buf 每次至多转换 C 字节。
                while data.has_remaining() {
                    let count = data.remaining().min(chunk_limit);
                    send_data(&mut writer, data.copy_to_bytes(count)).await?;
                }
            }

            Err(frame) => match frame.into_trailers() {
                Ok(trailers) => {
                    if trailers_sent {
                        return Err(h3_message_error(
                            "body produced more than one trailer section",
                        ));
                    }
                    if content_length_remaining
                        .is_some_and(|remaining| remaining != 0)
                    {
                        return Err(h3_message_error(
                            "trailers produced before Content-Length was satisfied",
                        ));
                    }

                    trailers_sent = true;
                    let trailers = qpack.encode_trailers(stream_id, trailers).await?;
                    send_headers(&mut writer, trailers).await?;
                }

                Err(_unknown_http_body_frame) => {
                    // http_body 的未知扩展 frame 不映射到 HTTP/3 wire。
                }
            },
        }
    }
}
```

请求和响应的普通有内容路径先分别调用 `qpack.encode_request` / `qpack.encode_response`，再将已编码 HEADERS、Content-Length 和 Body 交给同一个私有 `send_message`。下面例子仅限第 12.1 节普通内容 policy；HEAD/304/CONNECT 等必须先分派，不得直接调用。

```rust
let remaining = parse_content_length(&parts.headers)?;
let headers = qpack.encode_request(stream_id, parts).await?;
send_message(writer, stream_id, headers, chunk_limit, body, remaining, &qpack).await?;

let remaining = parse_content_length(&parts.headers)?;
let headers = qpack.encode_response(stream_id, parts).await?;
send_message(writer, stream_id, headers, chunk_limit, body, remaining, &qpack).await?;
```

如果 `http_body::Body::Data` 只实现 `Buf`，每次只 `copy_to_bytes(min(remaining, C))`；已有 Bytes 切分后交给 transport，不制作整帧副本。一个输入 Body frame 可编码为多个 DATA frame，保持字节顺序和长度总和。Fixed/应用 Body 原始大块属输入预算，库新增的转换缓冲受 C 限制。

如果 header 或 payload 的提交中途被取消，现有 `RequestSendCommit` / `ResetOnDrop` 负责 reset stream；`send_frame` 不自建另一套事务状态。

### 13.5 发送提交与控制屏障

所有同方向 frame 由唯一发送任务顺序提交，不允许两个任务在 header 与 payload 之间插入另一个 frame。`feed(header) → feed(payload) → flush` 只有全部成功才算该 frame 本地提交完成；Sink 的 item 边界不属于协议。不因拆成两个 chunk 就取消现有 poll_ready/backpressure 或退出 guard。

上面的 `send_message` 是 Fixed/标准 Body 的内容路径示意；初始首部和 policy 在发送前校验。Request<Chunk> 的初始 HEADERS 已在 pair 交付前提交，owner 只执行其后 DATA/trailers/FIN 循环，不能再发送一次初始 HEADERS。上传管道读端复用同一私有 DATA sender，无需把上传重新包装为 ChunkBody。

BodyWriter 的 flush 屏障按已接受字节的累计位置执行。owner 读取管道时还要受下一个屏障位置限制，写完该前缀立即 flush 并回执；不能等下一次 write 或 EOF 才检查控制请求。同一 pending 控制操作保留在 writer 中，取消调用不重复提交。正常结束意图先发布，才关闭管道入口；只有正常结束意图 + 排空 + trailers（若有）+ transport close 成功才报告上传成功。仅管道 EOF 是 BodyAborted。

writer 在正常结束意图提交后 Drop 只放弃回执，owner 继续完成；这与 owner 执行中的 send_frame 被方向取消/连接失败而丢弃不同，后者必须走 reset guard。回执、部分提交和错误保留按 [交换运行契约](../../dhttp/design/public-api/exchange/runtime.md#3-exec-与两个方向) 执行。

## 14. Error 映射

| 情况 | 结果 |
| --- | --- |
| frame 之间 clean EOF | `Ok(None)` |
| clean EOF 截断 type、length 或 payload | connection `H3_FRAME_ERROR` |
| transport connection failure | 保留 connection error 及 source |
| peer reset stream | 保留 stream reset code |
| frame 出现在错误 stream/阶段 | connection `H3_FRAME_UNEXPECTED` |
| SETTINGS 重复项或非法值 | connection `H3_SETTINGS_ERROR` |
| GOAWAY payload 有多余/缺少字节 | connection `H3_FRAME_ERROR` |
| GOAWAY 不满足本连接 profile 的 ID/边界规则 | connection `H3_ID_ERROR` |
| 非 DATA 聚合超过内部上限 | connection `H3_EXCESSIVE_LOAD` |
| blocked stream 数超过 `SETTINGS_QPACK_BLOCKED_STREAMS` | connection `QPACK_DECOMPRESSION_FAILED` |
| blocked field sections 的保留字节超过 connection 预算 | connection `H3_EXCESSIVE_LOAD` |
| DATA 总长度与 Content-Length 不一致 | stream `H3_MESSAGE_ERROR` |

`io::Error::other(transport::StreamError)` 仅是 `AsyncRead` 适配层的载体。`map_reader_error` 必须先 downcast 并恢复 transport error，不能将它统一改成 `H3_FRAME_ERROR`。

## 15. 最小验证

### 15.1 关键流式用例

```rust
#[tokio::test]
async fn data_is_streamed_and_the_next_header_is_preserved() {
    // transport chunk 1: DATA header + "ab"
    // transport chunk 2: "cd" + HEADERS header + HEADERS payload
    let input = chunks([
        bytes![DATA, 4, b'a', b'b'],
        bytes![b'c', b'd', HEADERS, 2, 0x00, 0x00],
    ]);

    let mut frames = FrameReader::new(ChunkReader::new(input));

    let data = frames.next_header().await.unwrap().unwrap();
    assert!(matches!(data.frame_type, FrameType::Data));
    assert_eq!(data.length, 4);
    assert_eq!(frames.read_payload_chunk(16 * 1024).await.unwrap().unwrap(), b"ab");
    assert_eq!(frames.read_payload_chunk(16 * 1024).await.unwrap().unwrap(), b"cd");
    assert!(frames.read_payload_chunk(16 * 1024).await.unwrap().is_none());

    let headers = frames.next_header().await.unwrap().unwrap();
    assert!(matches!(headers.frame_type, FrameType::Headers));
    assert_eq!(frames.read_payload(MAX_BUFFERED_FRAME_PAYLOAD).await.unwrap(), b"\0\0");
}
```

这个用例同时验证：

- DATA 不聚合整帧。
- transport chunk 可以在任意位置切分。
- DATA 末尾与下一帧 header 处于同一 transport chunk 时，剩余字节不会丢失。

### 15.2 其他必要用例

- VarInt 的 1/2/4/8 字节边界跨 chunk 读取。
- clean EOF 与 truncated frame 的区分。
- 未知 frame 跨多个 chunk 丢弃后正常解析下一帧。
- SETTINGS 多项、重复项、截断 VarInt 和未知 setting。
- `send_frame(DATA, original_bytes)` 产生 header chunk 和原 payload chunk，而非连续整帧副本。
- WebTransport 分类后，HTTP 分支收到完整首 header，WT 分支的 reader 正好位于 session ID 之后。
- 两条 blocked stream 分别要求 insert count 2 和 4；表到达 2 时只有第一条 oneshot 就绪。
- blocked stream 被取消后从 registry 移除，payload/guard 析构后归还字节预算。
- 单帧不超上限，但多条 blocked HEADERS 之和超过 `MAX_BLOCKED_FIELD_SECTION_BYTES` 时失败。
- QPACK connection 失败会结束所有 blocked waiters，不依赖后续 insertion。

### 15.3 补充契约验收

- 在每个 VarInt 字节、header/payload 之间插入 Pending：继续 poll 同一 future 不丢字节；中途取消只终止该方向，不重建解析器。
- DATA header/payload 两次 feed 分别 Pending/失败/取消，验证没有重复 header、guard reset、错误 code/source 未改变。
- transport 大 chunk 包含超过 C 的 DATA 和下一帧，单个输出 <= C；4 个队列槽加一个在途块 <= W，满队列时停止业务读取而关键流仍推进。
- 连续空 chunk、零 DATA、未知帧触发公平让出；其他 stream 和取消能推进。
- 半帧 EOF、reset、连接失败分别保持正确范围；队列满时连接失败先广播；显式 EOF/error 后永不再产出，队列意外断开为 OwnerStopped。
- 多条尚未读满的 HEADERS 同样受连接聚合总预算限制；所有大小恰好边界成功，超一字节失败；超限在分配前发生。
- RIC 就绪但故意不 poll waiter，继续注册新 blocked sections：字节预算不提前释放；解码/取消后才恢复。
- 延迟 waiter 期间 insert count 跨越 `2 * MaxEntries`，仍使用原 RIC/Base，不能错误进入新一轮 blocked；非法或已淘汰引用明确失败。
- QPACK 注册前后取消、唤醒后取消、connection failure 与 oneshot 关闭同时发生：无泄漏、无重复确认、优先保留原始 failure。
- 1xx 多次后 final、101、HEAD/304 非零 Content-Length、204 非法字段、普通 CONNECT 交接门禁、trailers 后未知帧与非法 DATA 分别覆盖。
- GOAWAY 两种本地发起者 ID、边界下降/上升、push 位置/ID 错误以及 WebTransport SETTINGS 回归；不混淆标准角色与对称 profile。
- pair 交付前 HEADERS 只发一次；flush 无后续 write 仍可完成；结束意图提交后丢弃 writer 仍能 FIN，owner 中途取消则 reset。

这些是实现时必须留下的可运行用例，不声称本文伪码已经通过。沿用现有测试和 fuzz 入口，frame fuzz 应覆盖实际新 parser，而不只保留旧连续缓冲 decode_frame 的影子路径。

## 16. 预计改动边界

- `src/wire.rs`：VarInt 异步读取、`ChunkReader`、`FrameReader`、payload parser 和 frame sender。
- `src/connection.rs`：将请求、响应和 control stream 读取改为 header/payload 两阶段；DATA 改为 chunk 交付。
- `src/qpack.rs`：删除 insertion 的全局 `Notify`，改为等待 decoder 返回的 per-stream oneshot；encoder stream 只唤醒新满足的 stream。
- `src/qpack/decoder.rs`：blocked entry 保存绝对 RIC 和 oneshot sender；field-section future 保存 prefix 和预算 guard，维护 connection 聚合及 blocked 子预算。
- `src/webtransport.rs`：仅调整双向流分类入参，不改协议行为。
- `Cargo.toml`：声明与 qbase 兼容的直接 `nom` 依赖；AsyncReadExt/ReadBuf 路径开启 Tokio `io-util`。核对实际解析器版本，不照抄未编译的 combinator 写法。
- `dhttp`：frame codec 实现无需改生产代码；设计文档同步链接契约。

### 16.1 实现顺序与完成口径

1. wire：ChunkReader/FrameReader、qbase VarInt、受限聚合、DATA/unknown chunk、分块发送；迁移请求/响应/control/WT 所有旧调用者，保留内部 Body 桥梁。
2. QPACK：保存 prefix、定向唤醒、预算 guard 与取消/失败清理；独立提交可评审。
3. exchange：按新版三成员 ChunkBody 和 AsyncWrite BodyWriter 接入 owner、队列和全局准入，不在 wire 提交创建公共 API 骨架。

每步须通过相关现有测试与新增边界用例、默认及 webtransport feature 编译；最终按 exchange/transport 文档执行 wasm 编译与非 Send 本地运行门禁。第一步完成不能标记 ChunkBody/owner/wasm 全部实现完成。普通 CONNECT 隧道和真实浏览器后端仍是后续独立设计，不阻塞 frame codec。
