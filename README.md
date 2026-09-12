# 两方门限 ML-DSA（2-of-2，无协调方，P_b 兼任 DFSS 比较方 C_b）

两个对称参与方 **P0**、**P1** 协作产生一份**标准 ML-DSA 签名**。外部验证者用普通
FIPS 204 验证接口即可验签，看不到任何门限成分。

与上一版（`P1` 兼协调方 + 独立比较节点 `C0/C1`，共四个进程）相比，本版本有两处结构性改动：

1. **取消协调方**。两方运行同一份顺序代码，每一步都是“同时交换”；签名由两方各自
   独立组装、各自用标准接口验证，最后交换签名摘要确认一致。没有任何一方替另一方
   “声明”打开值，也没有任何一方独占比较结果。
2. **取消独立的 FSS 比较服务器**。令 `C0 = P0`、`C1 = P1`：`P_b` 本来就持有 `z` 的加性
   份额 `z_b`，因此原来“把 `z_i` 再随机拆成两份分别发给两台比较机”这一步整体消失。
   进程数从 4 降到 2。

---

## 1. 目录结构

```
include/            公共头文件
src/sign/src/       协议实现（C）
src/sign/dispatch/  运行时参数集分发器（单一 node 入口，含 44/65/87）
src/dcf/            DFSS/EzPC 适配器（C++，随项目自带）
config/sign/        拓扑与私有身份
scripts/            构建与运行脚本（gen_message.py 生成待签消息，report.py 汇总表）
build/dfss/         DFSS 适配器构建产物（与参数集无关）
build/sign/         三种参数集的协议目标文件
logs/ runtime/      运行输出
```

协议实现的分层（每个文件的文件头注释写明了它的职责与边界）：

| 文件 | 职责 |
| --- | --- |
| `common.h` / `field.c` | ML-DSA 参数、模 q 运算、24 比特打包 |
| `mldsa_math.c` | 挑战乘法、`A·s`、高低位分解、Algorithm 7、审计承诺 `com` |
| `mldsa_compat.c` | FIPS 204 编码与标准验证 |
| `channel.c` | 两方 TCP 信道：同时交换、先承诺后打开 |
| `config.c` | 配置解析（旧四节点字段会被显式拒绝） |
| `party.c` | 生命周期、握手、度量、结果输出 |
| `dkg.c` | 两方 DKeyGen |
| `dcf_rejects.c` | DCF 离线池与在线批量比较（本方即 `C_b`） |
| `sign.c` | 签名主循环 |
| `open_check.c` | 打开一致性检查 |
| `mock_dcf.c` | **仅自检用**的进程内 DFSS 替身（不安全） |

---

## 2. 新物理机部署（一次配置、一次编译、多次运行）

### 2.1 系统要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Ubuntu 20.04 / 22.04 / 24.04 |
| 编译器 | gcc/g++ ≥ 9（EzPC 需要 C++17），binutils（`ld`、`objcopy`） |
| 构建工具 | make、cmake ≥ 3.16、git、python3 ≥ 3.8 |
| 内存 | ≥ 8 GB |
| 磁盘 | ≥ 10 GB |
| 网络 | 首次构建需能访问 GitHub |

### 2.2 第三方依赖

| 依赖 | 版本 | 用途 | 必需 |
| --- | --- | --- | --- |
| EzPC / SCI + FSS | `master` | 真实 DFSS 比较后端（半诚实） | 是 |
| OpenSSL / GMP / NTL / libsodium / Eigen3 / Boost | 发行版自带 | EzPC 编译依赖 | 是 |

本版本**不需要 MP-SPDZ**，代码与构建脚本中没有任何对它的引用；如果机器上还留着
MP-SPDZ 目录，可以直接删除。当前阶段也不使用 MAC（见第 6、7 节）。

### 2.3 一次性配置 + 编译

```bash
bash scripts/build_dependencies.sh                 # 系统包 + EzPC + 本项目 + 自检
bash scripts/build_dependencies.sh --skip-system   # 已装好系统包
```

或手动：

```bash
make                                   # 自动探测 EzPC；探测不到时按提示执行下一行（只需一次）
make EZPC_ROOT=/absolute/path/to/EzPC  # 路径会写入 config/toolchain.local.conf
```

EzPC 路径的**唯一**存放位置是 `config/toolchain.local.conf`（本机文件，不共享）。
相对路径以项目根目录为基准。`make` 会按以下顺序查找并自动写回：
`EZPC_ROOT` 变量/环境变量 → `config/toolchain.local.conf` → 自动探测
（`<项目>/third_party/EzPC`、`<项目>/../third_party/EzPC`、`<项目>/../EzPC`、`~/EzPC`）。

`make` 只产生**一个**二进制 `src/sign/node`，它同时包含 ML-DSA-44/65/87 三套实现：
协议源码分别以三种参数集编译、各自部分链接并把内部符号本地化，再与一个运行时分发器
链接在一起。DFSS 适配器与参数集无关，只构建一份。之后换参数集**不需要重新编译**。

### 2.4 验证构建

```bash
./src/sign/node modes                  # 输出 44 65 87
ldd src/sign/node | grep dfss          # 已链接真实适配器
make selftest                          # 协议自检（进程内替身，产物 node-selftest），三种参数集
bash scripts/run_local_simulation.sh   # 单机两进程完整签名，末行应为 ACCEPT
```

---

## 3. 运行

一次运行分三步，`scripts/run_local_simulation.sh` 会按步骤打印：

```
[1/3] 生成待签消息   scripts/gen_message.py  → logs/<本次运行>/message.txt
[2/3] 执行两方协议   src/sign/node ×2        → 只读第 1 步那份消息文件
[3/3] 汇总与复验     scripts/report.py       → logs/<本次运行>/report.txt
```

### 3.1 待签消息是先落盘、再签名的

消息不再只是命令行里的一个字符串：第 1 步先由 `scripts/gen_message.py` 把它写成
`logs/<本次运行>/message.txt`（另附 `message.meta.json`，含长度与 SHA-256/SHA3-256），
第 2 步两个节点通过 `--message-file` 读同一份字节。这样日志里留下的就是**真正被签名
的那份内容**，而且两方读到的是不是同一份，握手阶段就会校验出来（消息摘要参与握手比对）。

```bash
# 默认：自动生成带运行号/UTC 时间/随机 nonce 的消息，每次运行都不同
bash scripts/run_local_simulation.sh --mldsa-mode 44

# 指定文本
bash scripts/run_local_simulation.sh --mldsa-mode 44 --message "hello"

# 其它来源
bash scripts/run_local_simulation.sh --message-mode random --message-bytes 256
bash scripts/run_local_simulation.sh --message-mode file --message-source ./contract.txt
```

消息上限 1023 字节且不能含 NUL 字节（节点按 C 字符串处理）。也可以单独调用生成脚本：

```bash
python3 scripts/gen_message.py --out-dir /tmp/msg --mode timestamped
./src/sign/node <config> --message-file /tmp/msg/message.txt
```

### 3.2 单机模拟（参数集运行时选择）

```bash
bash scripts/run_local_simulation.sh --mldsa-mode 44 --message "hello"
bash scripts/run_local_simulation.sh --mldsa-mode 65 --message "hello"
bash scripts/run_local_simulation.sh --mldsa-mode 87 --batch-size 1 --pool-size 8 \
  --pool-mode refill --open-check strict --timeout 900 --message "hello"
```

输出目录 `logs/local-m<mode>-<时间戳>/`：

| 文件 | 内容 |
| --- | --- |
| `message.txt` / `message.meta.json` | 本次真正被签名的消息及其摘要 |
| `p0.log` / `p1.log` | 两方完整日志（含 DFSS 适配器的 `DFSS_CORE_*` 行） |
| `p0/`、`p1/` | 各方的 `public_key.bin`、`signature.bin`、`message.txt`、`summary.json` |
| `report.txt` / `report.json` | 第 3 步生成的汇总表（也会打印到控制台） |

### 3.3 汇总表怎么读：两类通信量是分开计量的

```bash
python3 scripts/report.py logs/local-m44-<时间戳>          # 事后随时重新生成
```

表里 `ctrl_*` 与 `dfss_*` 是**两条不同的链路**，不要相加成一个“信道”：

- `ctrl_sent_KiB / ctrl_recv_KiB`：P0↔P1 协议信道，来自各方 `summary.json`。
  份额交换、承诺打开、一致性检查走这里，量级是几十 KiB。
- `dfss_calls / dfss_core_ms per call / dfss_wire_KiB per call`：DFSS/EzPC 适配器
  自己那条连接，来自日志里的 `DFSS_CORE_*` 行。`dfss_wire_KiB = 两侧 sent 之和`，
  即链路上真实传输的字节数，与旧版四节点工程 `dfss_wire_kib/call` 口径一致。

**离线阶段的 `dcf_prep sent_bytes=48` 不是通信量下降**：那 48 字节只是两方在协议信道上
同步“池区间 / 池是否就绪”。真正的离线开销全部在 DFSS 栈内部——ML-DSA-44、1024 lane
时每个池项约 `13167.5 KiB ≈ 12.9 MiB`（C0 发 5,430,784 B + C1 发 8,052,736 B），
在线每次批量比较约 `87.98 KiB`。这两个数与旧版逐字节相同，只是旧版把它们并进了同一张表，
而节点自身的 `summary.json` 里从来就没有它们。所以要看总账，请以 `report.txt` 为准。

### 3.4 两台物理机

在两台机器上都（各自执行一次 `make`）：

```bash
# 1) 填 IP（两台内容必须完全一致）
vi config/sign/common.physical.conf     # 替换 REPLACE_WITH_P0_IP / REPLACE_WITH_P1_IP

# 2) 分发私有身份：p0.conf+p0.seed 只放 P0 机器，p1.conf+p1.seed 只放 P1 机器

# 3) 准备同一份消息：在任意一台生成后拷到另一台
python3 scripts/gen_message.py --out-dir /tmp/msg --mode timestamped
scp /tmp/msg/message.txt 对方主机:/tmp/msg/message.txt

# 4) 大致同时启动（P1 会在超时内反复重试连接 P0），两边 --mldsa-mode 必须相同
bash scripts/run_physical_node.sh --node p0 --mldsa-mode 65 --message-file /tmp/msg/message.txt
bash scripts/run_physical_node.sh --node p1 --mldsa-mode 65 --message-file /tmp/msg/message.txt
```

物理部署不做本机随机生成：两台必须签完全相同的字节，否则握手就会 `HANDSHAKE_FAILED`。
每台机器结束后只能看到自己那侧的 DFSS 记录；要合并两侧，把对方的日志目录拷过来再跑一次
`scripts/report.py`。

防火墙需放行：P0 的协议端口（默认 9001），以及两台机器各自的 DFSS 端口
`base`、`base+3`、`base+50`、`base+100`（默认 base 为 10101 / 10301）。

### 3.5 离线验签（按公钥长度自动识别参数集）

```bash
./src/sign/node verify logs/.../p0/public_key.bin logs/.../p0/signature.bin logs/.../message.txt
```

---

## 4. 配置项

公共拓扑（两台机器必须一致）：

| 字段 | 说明 |
| --- | --- |
| `party=<b>,<ip>,<port>,<dfss_port>` | 两行，`b∈{0,1}`。`port` 是协议信道端口（只有 P0 监听）；`dfss_port` 是该方 DFSS 基端口 |
| `mldsa_mode` | 44/65/87，运行时选择（由 `--mldsa-mode` 写入本次运行的配置） |
| `dcf_batch_size` | 一批候选数 K，1..8 |
| `dcf_pregen_pool_size` | 离线池容量 L，K..64 |
| `dcf_pool_exhaustion_mode` | `fixed`（耗尽即停）/ `refill`（续生成） |
| `open_check_mode` | `strict` / `off` |
| `worker_threads` | DFSS 在线阶段线程数，0=自动 |
| `timeout_seconds` | 单次收发超时 |

私有身份（各自机器一份）：`self_index=0|1`、`private_seed_file=...`。

本机工具链（不共享）：`config/toolchain.local.conf` 中的 `ezpc_root=`。它**不属于**协议配置，
写在 `common.*.conf` 里是无效的（节点会忽略，构建也不会从那里读取）。

握手阶段会逐项比对上述参数与**待签消息的摘要**，任何一项不一致都会
`HANDSHAKE_FAILED`。这条规则也意味着：两方必须各自同意同一条消息，不存在某一方
替另一方决定签什么。

## 5. 终止原因

| `terminal_reason` | 含义 |
| --- | --- |
| `SUCCESS` | 两方都得到同一份通过标准验证的签名 |
| `HANDSHAKE_FAILED` | 参数或待签消息不一致 |
| `CHANNEL_ERROR` | 连接断开、超时或帧失步 |
| `DKG_FAILED` | 密钥生成失败 |
| `DCF_ERROR` | DFSS keygen/eval 失败，或双方池区间不一致 |
| `PREPROCESSING_EXHAUSTED` | `pool_mode=fixed` 且离线池用尽 |
| `POOL_REFILL_FAILED` | 续生成失败 |
| `OPEN_CHECK_FAILED` | 两方视图不一致 |
| `VERIFY_FAILED` | 组装出的签名过不了标准验证 |
| `PEER_DISAGREE` | 两方签名摘要不同 |

## 6. 安全边界（请勿在论文中写过头）

本实现提供的是**半诚实**结构下的两方门限签名。以下四点是协议层面的边界，不是实现缺陷，
运行日志中的 `audit:` 一行会把第 1 点的实测数值打印出来：

1. **任一方在一次签名后即可恢复 `s2`（进而恢复 `s1`）**。两方都知道完整的 `w`、`z`、`t`，
   而 `A z − c t = w − c s2` 是恒等式，因此 `c·s2` 可直接算出。
2. **`‖z‖∞` 的 DCF 检查在当前 nonce 参数下几乎不会拒绝**：每方份额界为
   `(B−4096)/2`，聚合后 `|z| ≤ B−4096+2τη < B`。实测 8 次尝试全部由 DCF 判通过，
   拒绝全部来自 `r0`，而 `r0` 是在明文上算的。
3. **被 Algorithm 7 拒绝的候选，其 `z` 已经向双方打开**。只有被 DCF 判拒的候选才真正
   没有打开过 `z`。要做到“只在接受后才打开”，必须把 `r0`/`ct0`/hint 判定也放进 MPC。
4. **`open_check` 不是恶意安全检查**。两方之间每条消息只发给唯一的对方，不存在
   equivocation，双方视图都是同一份转录的确定性函数；它检测的是传输错误、状态机分叉与
   实现缺陷，恶意一方可以直接在压缩值上说谎。

此外，DKG 没有可验证秘密分享（VSS），也没有机制把某一方绑定到它在 DKG 中的份额；
这类偏离会导致签名过不了验证（DoS），而不是伪造。

伪代码与逐步推导见同目录下的 `main.tex`。

## 7. 安全模型的演进路线

按“功能正确 → 半诚实 → 恶意安全”三步推进，每一步的总体目标：

- **功能正确（当前所处阶段）**：两方协作输出能通过标准 FIPS 204 验证的签名，接口、状态机、
  测试与度量框架齐备。允许存在第 6 节列出的中间值泄露。
- **半诚实安全**：假设双方严格按协议执行，要求任一方的全部视图（收到的消息 + 自己的份额与随机数）
  都能仅凭它自己的输入和最终签名模拟出来。对本项目而言，核心是消除第 6 节第 1、3 点：
  不公开完整 `t`/`w`，把全部拒绝判定（`z` 范数、`r0`、`ct0`、hint）放进 MPC，只有被接受的候选才打开，
  并给出基于模拟的证明。**这一步不需要 MAC**。
- **恶意安全（带中止）**：对手可任意偏离协议，要求任何偏离要么被检测到并中止，要么不影响输出正确性与私钥保密性。
  需要认证份额（SPDZ 类 MAC）或零知识证明、可验证 DKG、恶意安全的 OT/DCF 密钥生成与打开检查。
  MAC 属于这一步的工具。两方场景下一般只能做到“带中止”的安全，无法保证公平输出。
