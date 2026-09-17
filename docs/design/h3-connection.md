# H3Connection：任务归属与伪代码

状态：已按此设计完成 Rust 重构。本文保留任务归属与流程伪代码，实际实现见 `src/protocol/connection.rs`、`src/protocol/qpack.rs` 和 `src/protocol/stream/`。

**新增 GOAWAY 约定：收到对端 GOAWAY 后立即触发本端 GOAWAY 回应；本端已发送过则不重复发送。本次回应写完、正在运行的请求流处理完后，主动以 H3_NO_ERROR 关闭 QUIC。control 和 QPACK 随底层连接终止而退出，不再等待 idle timeout。**

排空只等待请求 / 响应双向流的两端结束或取消。control、QPACK 流不在排空集合内，它们在排空期间继续工作。

## 1. 不保存任务句柄

Connection 只启动 accept_uni、accept_bi 两个接流任务。QPACK 内部启动 encoder、decoder 的发送任务，cursor 内部启动 control 发送任务。退出原因来自真实 I/O 或现有 transport 的终止结果；各组件都不保存 JoinHandle。

`tokio::spawn` 返回的句柄被丢弃后，任务仍会运行；因此每个任务必须在自身边界处理失败，不能仅返回一个无人接收的 `Err`。[Tokio JoinHandle](https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html)。

队列保存待发送的指令或待交付的流，任务消费队列并执行实际 I/O。发送任务归对应组件管理，不将三个发送任务再集中放回 Connection。

### 结构草图

```rust
pub struct H3Connection<T: Transport> {
    transport: Option<Arc<T>>,
    settings: Arc<Settings>,
    qpack: Arc<Qpack<T>>,
    cursor: Arc<Mutex<StreamCursor>>,
    bi: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
}

pub struct Qpack<T: Transport> {
    transport: Arc<T>,
    encoder: Mutex<Result<Encoder>>,
    decoder: Mutex<Result<Decoder>>,
}
```

- `transport: Some(...)` 表示连接句柄仍承担 Drop 时关闭 transport 的责任；成功完成 `goaway(self)` 的交换后取出这一引用，control 接收任务继续负责排空并关闭 transport。它直接表达资源所有权，不另加“任务已脱离”布尔标记。
- QPACK 保留同一 transport 的引用，让请求侧 `decode` 发现连接级协议错误时能直接关闭它。这样不需要额外错误 channel，也不依赖某个 reader 下次恰好收到数据。
- 这个选择会使接收 `Arc<Qpack>` 的消息函数相应增加 `T` 泛型；纯 encoder / decoder 算法仍可独立于 transport 测试。
- cursor 保留两个方向的边界及实际 GOAWAY 操作的等待结果。它不存放全局错误状态或任务句柄。
- bi 负责请求流登记和已接纳流的交付。后台 accept_bi 是底层双向流接收者；上层 receive_bi() 从交付队列取流，不再调用底层 accept。
- 不增加 `ConnectionStatus`、`Runtime`、`EncoderHandle`、`DecoderHandle`、`Critical` 或全局错误广播。

错误沿操作返回；仍被共享持有的失效资源替换为 `Err` 或已有枚举终态。沿用先前 15 个相关任务确定的约束：不恢复开流前后 `self.error()` 检查、重复 ID 校验、`closed()` 和单纯转发的包装。

## 2. 哪些等待能直接靠流终止结束

| 当前等待 | 退出来源 |
| --- | --- |
| QUIC read / write / open / accept | 原 I/O 返回结束或错误 |
| encoder 的 `rx.recv()` | channel 自身关闭，或同时等待已有 `transport.terminated()` |
| decoder 的下一条反馈 | 原队列的 writer Waker，或同时等待已有 transport 终止 |
| control writer 等待本地 GOAWAY | cursor 中该次操作的 Waker，或已有 transport 终止 |
| decode 等待动态表 | 已有 decode Waker；transport 结束后原 decoder 变为 Err |
| 等待 GOAWAY 交换 | 实际写入结果、收到的 GOAWAY、已有 transport 终止 |
| 请求发送操作 | 原 write / shutdown 结果；适配器提供停止 future 时，由本次发送 future 直接等待 |

网络流关闭不会自行关闭一个独立的 mpsc channel。等待 channel 时复用 `Transport::terminated()` 是等待底层连接本身，未增加新的通知机制。[Tokio mpsc Receiver](https://docs.rs/tokio/latest/tokio/sync/mpsc/struct.Receiver.html)。

**GOAWAY 写完后不能关闭 control 流来表示任务完成。** control 和 QPACK 流属于关键流，仍需支持存量请求；完成一次协议操作和结束该流是两件事。[RFC 9114 §6.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1)、[RFC 9204 §4.2](https://datatracker.ietf.org/doc/html/rfc9204#section-4.2)。

## 3. 伪代码记号与收尾

以下是流程伪代码，省略锁的拼写、类型参数和错误转换，不是可编译 Rust。锁内只做同步状态修改，网络 I/O 和等待队列容量都在锁外。

- `SPAWN`：启动任务，不保存句柄。
- `TRY / ON ERROR`：该任务自己的失败分支。执行失败分支时，本任务的 QUIC half 仍然存活；处理后直接返回，返回时释放资源。
- `AWAIT` 和同步协议操作产生的 Err 向外返回，进入最近的任务错误分支；不忽略错误后重新进入 LOOP。
- `RACE 工作 WITH transport.terminated()`：保留工作 future，直到它完成或底层连接终止。只有连接已终止时才取消未完成的工作，不因其他业务事件重建半读、半写操作。
- `use(resource)`：直接匹配 `Result<Resource>`；是访问资源的入口，不是提前读取另一份 error。
- `close_connection(error)`：复用当前关闭入口，关闭 transport、将 QPACK 的活资源替换为 Err，并使存量流进入原有终态。只唤醒这些资源已经登记的等待者。

主动连接级错误调用 `close_connection`。已由 transport 终止导致的返回只按其结果清理本地资源，不重新选择一个协议错误原因。

所有任务退出前处理结果，再释放其持有的流。没有 `task.abort()`、额外取消 token 或任务结束 Notify。

循环只用于连续处理正常的流、帧和指令。任务遇到错误、输入结束或接纳被拒绝时，完成该分支的收尾后返回；不继续循环，也不自动重启任务。普通请求级错误仍只结束相应请求，连接级错误按原职责关闭连接。

### 初始化

Connection 中仅保留两个接流任务的启动：

```text
Connection::new(transport, settings):
    构造 settings、BiStreams
    qpack = Qpack::new(transport, settings, bi)
    cursor = StreamCursor::new(transport, settings, qpack, bi)

    SPAWN accept_uni
    SPAWN accept_bi

    返回 H3Connection
```

三个发送任务由各自组件初始化并启动，伪代码省略重复的共享引用参数：

```text
Qpack::new(...):
    构造 encoder、decoder 及共享 QPACK 对象
    encoder 的 tx 留在 encoder；rx 移给发送任务
    decoder 保留原有反馈队列及 writer 等待者

    SPAWN encoder_send(rx)
    SPAWN decoder_send
    返回 qpack

StreamCursor::new(...):
    构造两个方向的 cursor 及 GOAWAY 操作
    SPAWN control_send
    返回 cursor
```

| 所属组件 | 启动的任务 | 工作来源 |
| --- | --- | --- |
| Connection | accept_uni、accept_bi | 底层接流操作 |
| QPACK encoder | encoder_send | encoder 的指令 tx / rx |
| QPACK decoder | decoder_send | decoder 的反馈队列 |
| cursor | control_send | 本地 SETTINGS 和一次 GOAWAY 意图 |

control 只有一次 SETTINGS 和本端的一次 GOAWAY，继续使用 cursor 的单次交付，不为统一队列外形增加通用帧队列。三个发送任务都与自己的数据来源放在一起。

三个 reader 在收到对应单向流后启动。流类型读取任务随后直接成为该 reader，不再多 spawn 一层。

## 4. 单向流接收与分派

### 任务 A：accept_uni

此任务直接等待 accept。transport 终止由 accept 本身返回错误，错误分支完成资源清理；不再并列等待 transport.terminated()。

```text
TASK accept_uni:
    LOOP:
        MATCH AWAIT transport.accept_uni_stream():
            Ok((_, recv)):
                SPAWN:
                    TRY:
                        type = AWAIT 读取 recv 的完整单向流类型
                        如果完整类型出现前已经 FIN / RESET:
                            RETURN

                        MATCH type:
                            0x00:
                                认领唯一的 peer control 流
                                AWAIT control_receive(&mut recv)
                            0x02:
                                认领唯一的 peer encoder 流
                                AWAIT encoder_receive(&mut recv)
                            0x03:
                                认领唯一的 peer decoder 流
                                AWAIT decoder_receive(&mut recv)
                            0x01:
                                返回当前不支持 push 的协议错误
                            未知类型:
                                recv.stop(H3_NO_ERROR)
                                RETURN
                    ON ERROR error:
                        close_connection(error)
                        RETURN Err(error)
                    RELEASE recv
            Err(error):
                qpack 的活资源替换为 Err(error)
                取出并唤醒 decoder 已有的等待者
                bi.close(error)
                RETURN
```

每条流在独立的 SPAWN 块中读取类型并进入对应 reader，不阻塞后续 accept。认领沿用现有具名关键流标记；三个 reader 的错误返回所在 SPAWN 块的错误分支。

## 5. QPACK 的四个方向

### 任务 B：encoder_send —— 本端 encoder 流

```text
TASK encoder_send(rx):
    TRY:
        send = AWAIT transport.open_uni_stream()

        RACE:
            WRITE stream_type = 0x02
            LOOP:
                batch = AWAIT rx.recv()
                如果发送端已关闭:
                    返回 encoder 自身的失败结果
                    // 活跃关键流的指令来源意外消失不能静默成功

                FOR instruction IN batch:
                    encoder 开始本次写入记账
                    AWAIT send.write_all(serialize(instruction))
                    AWAIT send.flush()

                    在同一 encoder 锁内:
                        记录本条指令已写完
                        应用写入期间收到的已有反馈
        WITH transport.terminated()
    ON ERROR error:
        close_connection(error)
        RETURN Err(error)
    RELEASE send
```

`encode` 和 SETTINGS 导致的容量指令都进入同一个 tx。channel 自带唤醒，不再放 `encoder_ready: Notify`。批次排队、本地写入、对端反馈沿用现有 QPACK 记账，不作为新的连接状态。

### 任务 C：decoder_receive —— 读对端 decoder 流

```text
ASYNC decoder_receive(recv):
    LOOP:
        instruction = AWAIT DecoderInstruction.read(recv)

        在 encoder 锁内:
            encoder = use(qpack.encoder)
            如果当前指令写入尚未完成记账:
                放入现有的写入期间反馈缓冲
            否则:
                应用 SectionAck / StreamCancellation / InsertCountIncrement

        // 错误返回接收该流的 SPAWN 块
```

### 任务 D：encoder_receive —— 读对端 encoder 流

```text
ASYNC encoder_receive(recv):
    LOOP:
        instruction = AWAIT EncoderInstruction.read(recv)

        在 decoder 锁内:
            decoder = use(qpack.decoder)
            应用容量、插入或复制指令
            取出 Required Insert Count 已满足的 decode 等待者
            将新增插入进度纳入原有反馈队列 / 合并计数
            取出真正等待反馈的 writer Waker

        释放锁后唤醒这些等待者

        // 错误返回接收该流的 SPAWN 块
```

这里的唤醒来自新表项或真实反馈可读，不是错误广播。

### 任务 E：decoder_send —— 本端 decoder 流

```text
TASK decoder_send:
    TRY:
        send = AWAIT transport.open_uni_stream()

        RACE:
            WRITE stream_type = 0x03
            LOOP:
                instruction = AWAIT poll_fn(cx):
                    decoder = use(qpack.decoder)
                    如果原有反馈队列 / 合并计数可产出指令:
                        RETURN Ready(instruction)
                    登记这个 writer 的 Waker
                    RETURN Pending

                AWAIT send.write_all(serialize(instruction))
                AWAIT send.flush()
        WITH transport.terminated()
    ON ERROR error:
        close_connection(error)
        RETURN Err(error)
    RELEASE send
```

这里选择沿用 decoder 的原有反馈队列和一个实际 writer Waker，不再并列增加 channel 与 Notify。这样 decode 的取消路径仍能同步提交 StreamCancellation。

### 请求侧 encode / decode / cancel

这些由请求任务调用，不再分别 spawn 编解码任务。

```text
encode(stream_id, fields):
    在 encoder 锁内:
        encoder = use(qpack.encoder)
        准备字段段和对应指令
        在提交动态表变化前非阻塞地预留 channel 容量
        将变化和指令按同一顺序提交
        RETURN 字段段字节

    容量不足继续采用现有静态索引 / 字面量退路
    普通请求级错误直接返回
    连接级错误先关闭 qpack 持有的 transport，再返回 Err
```

```text
ASYNC decode(stream_id, payload):
    登记原有 decode 等待项，字段段字节留在本 future

    result = AWAIT 原有 poll_decode:
        decoder = use(qpack.decoder)
        表项未到时登记本请求 Waker，返回 Pending
        表项已到时解码
        成功且 Required Insert Count 非零:
            向原有反馈队列提交 SectionAcknowledgment
            唤醒实际等待该队列的 writer
        返回字段段 / 解码错误

    清理原有等待注册
    如果 result 是连接级协议错误:
        直接关闭 qpack 持有的 transport
        // accept_uni 随后由 accept 返回的错误清理其他共享资源
    RETURN result

取消 decode future / cancel(stream_id):
    复用原有取消路径释放等待项
    decoder 仍有效时，同步提交 StreamCancellation
    唤醒正在等该反馈的 writer
```

插入进度反馈与 Section ACK 的触发时机继续按 QPACK 区分。[RFC 9204 §2.2.2](https://datatracker.ietf.org/doc/html/rfc9204#section-2.2.2)。

## 6. Cursor 与 control 的两个方向

cursor 继续以枚举表达本地 `Max → Gone` 和收到的 peer 边界。伪代码中的等待都是对应协议操作的等待：

| 操作 | 由谁等待 | 由谁完成 |
| --- | --- | --- |
| 取得本地 GOAWAY 边界 | control writer | 主动 goaway 或自动回应时的 cursor 转换 |
| 本地 GOAWAY 写入结果 | goaway 调用方 | 唯一 control writer |
| 取得 peer GOAWAY | goaway 调用方 | 唯一 control reader |

保留现有被消费的写入结果，删除未使用的每帧 oneshot 回执；不额外保存 `local_written`、`goaway_received` 或任务结束通知。cursor 的 poll 在同一把锁里检查状态、登记真实等待者，变化后在锁外唤醒。

### 任务 F：control_send

```text
TASK control_send:
    TRY:
        send = AWAIT transport.open_uni_stream()

        RACE:
            WRITE stream_type = 0x00
            AWAIT write_frame(send, SETTINGS(settings.local))
            AWAIT send.flush()

            boundary = AWAIT cursor 的本地 GOAWAY 操作
            AWAIT write_frame(send, GOAWAY(boundary))
            AWAIT send.flush()
            将 Ok(()) 交付给该次 GOAWAY 的实际写入结果
        WITH transport.terminated()

        AWAIT transport.terminated()
        // 写操作成功后继续持有 send；不发 FIN，不重写第二次 GOAWAY
    ON ERROR error:
        尚未交付的本次写入结果返回 Err(error)
        按实际错误处理连接 / 本地清理
        RETURN Err(error)
    RELEASE send
```

写结果只报告实际写操作的完成，不把任务退出当作 GOAWAY 完成。

### 任务 G：control_receive

```text
ASYNC control_receive(recv):
    frame = AWAIT read_control_frame(recv)
    校验首帧是 SETTINGS
    qpack.encoder 应用 peer SETTINGS
    保存 settings.peer

    继续读取并处理 control 帧，直到第一次收到 GOAWAY(id):
        在 cursor 锁内:
            校验方向及边界不能升高
            更新 peer 边界
            取出等待 peer GOAWAY 的实际等待者
            如果 local 仍是 Max:
                根据已接纳位置计算本地边界
                local = Gone(boundary)
                取出等待本地边界的 control writer Waker

        如果本次完成了本地 Max → Gone 转换，在锁外:
            唤醒 control writer             // 立即触发回应
        对 bi 中受 peer GOAWAY(id) 影响的本端请求应用该 peer 边界
        锁外唤醒等待者
        running = bi 中此时已登记的存量请求流

    RACE 以下两个 future:
        后续 control 帧读取:
            LOOP:
                frame = AWAIT read_control_frame(recv)
                如果又收到 GOAWAY:
                    按原规则更新 peer 边界、处理新增受影响的流
                    不再发送第二份回应，不重新启动排空
                否则:
                    沿用当前 control 帧处理规则

        本次排空:
            AWAIT 本地 GOAWAY 的实际写入结果
            AWAIT running 中每条请求流的两端结束或取消
            transport.close(H3_NO_ERROR)
            RETURN

    // 排空路径先关闭 QUIC，再结束另一个读取 future。
    // 读取错误返回接收该流的 SPAWN 块，在那里关闭连接。
    // 若 transport 提前终止，原读取 / 写入 / 流终态使这些等待退出。
```

`running` 是这次排空 future 持有的请求流列表，取自现有 BiStreams 登记表；它不成为新的连接字段。停止接纳后出现的新流不会扩大本次排空范围。等待检查已有请求流终态，由 `BiStreams` 统一持有一个排空 `Notify`，不新增收尾任务。

### goaway(self)：发起并等待交换

```text
ASYNC goaway(self):
    在 cursor 锁内:
        如果 local 仍是 Max:
            boundary = 根据已接纳位置计算边界
            local = Gone(boundary)
            取出等待这个边界的 control writer Waker

    如果本次完成了 Max → Gone 转换，在锁外:
        唤醒 control writer

    RACE:
        AWAIT 本次 GOAWAY 的实际写入结果
        AWAIT cursor 中的 peer GOAWAY
    WITH transport.terminated()

    成功后取出 self.transport
    // control_receive 已有 transport 引用，负责排空并主动关闭
    RETURN Ok(())

如果上述 future 在完成前被丢弃:
    self 仍持有 transport
    H3Connection::Drop 关闭 transport
```

主动发起和自动回应都在各自处理处完成同一项 cursor 转换。由锁内的 Max → Gone 保证只触发一次写入；原接流任务随后若收到新流，则拒绝该流并退出。已有 Gone 时，goaway(self) 仍继续等待交换，不提前返回。

`goaway(self).await` 的返回时机继续是本地 GOAWAY 已写完且已收到 peer GOAWAY；排空和主动终止由 control_receive 继续完成。若 transport 在交换确认前结束，则按其结果返回，不把连接关闭当作收到 GOAWAY。这里没有增加 GOAWAY ACK 或任务完成消息。

## 7. 请求流相关任务

### 任务 H：accept_bi —— 正常交付，拒绝后退出

```text
TASK Connection.accept_bi:
    LOOP:
        MATCH AWAIT transport.accept_bi_stream():
            Err(error):
                结束上层接流队列，使等待取流的调用得到该结果
                RETURN
            Ok(stream):
                在 cursor 锁内:
                    如果 local 仍是 Max:
                        cursor.accept(stream.id)
                        halves = bi.insert(stream)
                        将 halves 放入已接纳流的交付队列
                        CONTINUE

                // local 已是 Gone：拒绝当前流，结束这个接流任务
                stream.recv.stop(H3_REQUEST_REJECTED)
                stream.send.cancel(H3_REQUEST_REJECTED)
                结束上层接流队列，不再交付新流
                RETURN
```

正常阶段，任务完成接纳、登记、交付后继续循环。遇到 Gone 时拒绝当前流，结束交付端并返回；底层 accept 报错也直接返回。

接流任务持有 transport、cursor 和 bi 的共享引用，不借用整个 H3Connection。任务返回后不创建替代接流者；后续未接收的流由最终 QUIC 关闭结束。存量请求仍由 control_receive 等待排空，这个拒绝分支不提前关闭整个连接。

相应地，上层接口消费任务交付的结果：

```text
ASYNC H3Connection.receive_bi():
    RETURN AWAIT 已接纳流的交付队列
```

这条队列用于真正交付流，不是错误广播。入队时已经完成接纳，排队中的流也纳入 GOAWAY 排空范围；拒绝新流而结束交付端时，已排队的流仍可被取走，队列耗尽后上层得到接流结束结果。上层接收端被释放时，尚未取走的流通过原有流 Drop 路径取消，避免无人处理的队列阻止排空。

GOAWAY 只改变 cursor，不启动拒绝任务、不唤醒底层 accept。已经挂起的 accept 继续等真实接流结果；拿到流后，在同一把 cursor 锁内决定接纳并登记，或在锁外 stop / cancel 后返回。

### 读写方向由应用持有，连接只观察终态

`H3ReadStream<R>` 和 `H3WriteStream<W>` 分别保存流 ID 与本方向的共享状态。
`BiStream` 只保存状态的弱引用，不复制应用句柄，不延长底层流的生命周期。
应用句柄 Drop 时直接取消本方向，因此不需要 `cancel_on_drop` 区分句柄用途。

排空 future 直接检查两个方向的终态；弱引用已经失效也表示该方向结束。
共享状态为 `Result<H3Stream<T>, Goaway>`，只有 GOAWAY 拒绝保存在 `Err` 中。
`H3Stream` 保留 `Idle`、`Polling`、`Finished` 和临时 `Transition` 枚举；
`Polling` 中的唤醒器属于应用 I/O 任务。`Finished(T)` 保留底层流，
普通错误直接通过读写返回，不缓存首次错误，后续操作仍取得底层 I/O 的结果。
`BiStreams` 统一持有一个 `Arc<Notify>`；读写句柄不持有通知引用，方向完成时的通知方式待定。
`BiStreams::drained()` 先登记通知，再检查固定请求流集合中所有方向的终态；
未全部结束时等待通知，醒来后重新检查，避免检查与等待之间丢失唤醒。
目前 GOAWAY 或连接关闭后在状态锁外通知排空等待者；普通读写完成、取消和 Drop 的通知尚未接入，不引入 `Draining` 状态。
应用 I/O 继续使用 `Polling` 内的 waker，不被排空等待覆盖。

删除可选 STOP 通知输入及其构造接口。peer STOP/reset 通过底层
write / flush / shutdown 的错误返回给发送操作。等待应用提供 body 数据期间
不再独立观察 STOP；应用继续提供数据、结束或取消 body 后发送操作才继续推进。
发送失败仍写回 body 错误；客户端发送失败不丢弃有效响应。
不增加停止扫描任务或每流监视任务。

### open_bi

```text
ASYNC open_bi():
    stream = AWAIT transport.open_bi_stream()
    RETURN bi.insert(stream)
```

不在这些操作前后额外查询错误，也不重新检查 transport 已保证的流 ID 范围和种类。

## 8. Drop 与退出条件

```text
DROP H3Connection:
    释放上层接流端，取消队列中尚未取走的流
    如果 self.transport 中仍有引用:
        close_connection(H3_NO_ERROR)
    // 不 abort 任务；所有任务按上面的 I/O / transport 终止路径结束
```

| 事件 | 结果 |
| --- | --- |
| 普通连接句柄被 Drop | 关闭 transport，各任务退出 |
| goaway future 中途被 Drop | 同上，保留现有取消约定 |
| GOAWAY 交换成功 | control_receive 接管排空和关闭；关键流在此期间继续运行 |
| 本地 GOAWAY 已写完，存量请求流全部结束 | control_receive 主动关闭 QUIC，所有关键流和其他任务退出 |
| accept_bi 在 Gone 后收到新流 | 拒绝当前流、结束交付端并返回，不再继续接流 |
| 关键流读写 / 解析失败 | 在该任务边界关闭连接，其他任务由原终止路径退出 |
| 请求字段段发生 QPACK 致命错误 | 通过 QPACK 持有的 transport 直接关闭连接 |
| QUIC 提前 idle timeout / 对端关闭 | accept_uni 由 accept 返回的错误清理资源，其余任务自然退出 |
| writer 正在等待本地队列 / cursor | 原有 transport 终止 future 使它退出，不等待下一次业务数据 |
| decode 正在等待动态表 | decoder 活资源被替换为 Err，已有 Waker 使它返回 |

这里保证任务最终退出；不提供“所有任务已经 join 完毕”的同步屏障。当前 `Drop` 本来也是同步接口，不据此增加任务集合或完成广播。

## 9. 验证重点

实现复用并更新现有测试，同时为接流交付、排空范围、队列背压和终止清理补充回归测试：

- 删除 JoinHandle 后，普通 Drop 和 goaway 取消仍关闭 transport。
- Connection 初始化只直接启动 accept_uni、accept_bi；三个发送任务在 QPACK / cursor 内部启动一次。
- 后台 accept_bi 持续交付多条流，上层接口只取队列结果，不竞争底层 accept。
- encoder 队列为空、decoder 无反馈、control 尚未 GOAWAY 时，transport 结束能让任务退出。
- 没有任何 peer 关键流到达时，idle timeout 也能清理 QPACK 和存量流。
- 收到 GOAWAY 后回应不等待存量请求；已有本地 GOAWAY 时不重复回应。
- 排空期间 control / QPACK 保持运行、不发 FIN；存量请求结束后主动关闭 QUIC。
- 没有存量请求时，也必须先写完 GOAWAY 回应，再关闭连接。
- 等待排空时继续处理后续 control 帧；排空范围不被新流无限扩大。
- 部分指令 / 帧写入不会因无关事件取消后重写。
- decode 等待时连接终止、或请求侧解码发现致命错误，都能结束等待。
- 并发主动 GOAWAY 与自动回应仅转换一次，不额外启动接流任务。
- accept_bi 在 Gone 后拒绝当前流即返回，后续不再调用底层 accept，也不启动替代任务。
- 其他任务的读取、写入、解析或交付失败后，执行一次必要收尾并返回，不吞掉错误继续循环。
- 没有连接级停止扫描任务；已启动的发送 future 在等待 body 时也能处理其可选 STOP 输入。
- 发送方向收到 STOP 后，body 得到错误，接收方向仍能交付有效响应。
- 未轮询的发送 future 不消费 STOP；开始轮询后处理已到达的 STOP，直接 Drop 仍传播取消。
- GOAWAY 排空只观察请求流终态，不负责轮询停止输入，也不引入替代扫描任务。

领域含义见 [CONTEXT.md](../../CONTEXT.md)；标准客户端 GOAWAY 的 Push ID 与 h3x 对称请求流扩展仍按 [项目说明](../../README.md#server-initiated-requests) 区分。

## 10. 调用方迁移

`Qpack` 现在是 `Qpack<T: Transport>`，消息函数使用同一连接的 `Arc<Qpack<T>>`。从 `connection.qpack().clone()` 获取，不再使用无 transport 的 `Qpack::default()`。纯 encoder / decoder 算法仍可独立测试。

`goaway(self).await` 等待本地实际写完并收到对端 GOAWAY；排空由 control reader 继续完成。普通 Drop 或丢弃未完成的 goaway future 会关闭 transport，任务通过 I/O 与 transport 终止退出。
