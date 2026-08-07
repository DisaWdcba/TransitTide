# 从 Duck Eye 到 Elastic：看新兴堆栈攻防的演变

> 一次针对 [sleep_duck_eye](https://github.com/huoji120/sleep_duck_eye) 检测器的完整攻防实验记录——从三层检测机制解剖、通用绕过设计，到 Elastic 规则集的检测面守恒分析，最后推演 CET 影子栈时代的攻防形态。所有结论均来自本仓库可复现的实验。

---

## 一、起点：Duck Eye 凭什么"通杀"市面堆栈欺骗

鸭哥的`sleep_duck_eye`（下文称 Duck Eye）是一个检测睡眠混淆/堆栈欺骗的进程扫描器。它的检测逻辑分三层：

**第一层——帧属性检查（`SimpleCheckIn2020`）**

```
对栈上每个帧地址做 VirtualQuery：
  是 MEM_IMAGE（有映像背书）？→ 短路放行
  不是？→ 查页保护，RWX 私有内存 = 可疑
```

这是最朴素的一层：shellcode 通常住在 `VirtualAlloc` 出来的私有 RWX 里，帧解析不到任何模块。**MEM_IMAGE 是它的盲区开关**——只要帧属于某个已加载的 PE，这一层直接放行。

**第二层——指令流启发式（`TryFindValidDisasm`）**

```
读返回地址附近 [-0x20, +0x28) 的字节，capstone 反汇编，打分：
  能解出合法指令序列 → 通过
  解不出来（密文/垃圾）→ "Non-integrity"
```

这一层针对睡眠混淆：Ekko 类方案在睡眠时把代码页加密，返回地址正好指向密文——解码必然失败。打分规则是 2 分启发式：`mov` 等常规指令 +2 分，垃圾指令降分。

**第三层——call 目标解析（`CalcNextJmpAddress`）**

```
在窗口内找 call 指令，解析目标：
  RIP 相对 / 寄存器 / 内存间接 → 算最终目标
  目标非法（跳到随机地址）→ 检出
```

这一层针对"假 call"：有的绕过方案在窗口里放一条指向合法函数（如 Sleep）的 call 做掩护，但 call 目标是伪造的。Duck Eye 会真正算出来并验证。

**顺带修的两个真实 bug**（代码中有披露注释）：

1. `TryFindValidDisasm` 中 `cs_free(this->insn)` 之后立刻拷贝 `insList` —— use-after-free，破坏反汇编结果，导致真实 ntdll/kernel32 帧大面积误报；
2. `StackTracker` 构造器未初始化 `ins_ip/ins_ip_address/readSuccess` —— 垃圾字段让 `getNextIns()` 直接返回 nullptr，**每一个被扫的帧都像"Non-integrity"**。

修复前扫一个 notepad 满屏误报；修复后干净。这两个 bug 也说明：检测器的"通杀"能力建立在一堆脆弱启发式之上，而启发式就有绕过空间。

## 二、绕过设计：全量加密的死，与窗口加密的生

经典睡眠混淆（Ekko 式）把整个代码页加密。用 Duck Eye 验证这个对照组，结果非常干净利落：

```
SleepMask Encryption Memory Detected: <base+0x15>
```

第二层解码直接失败。**加密本身是可见的**——检测器不需要知道密钥，只需要发现"返回地址附近的字节不是合法指令"。

于是设计变成了：**加密要保留一个窗口**。

```
睡眠时 .pay 页内字节态（检测器扫描时刻的实测）：
  [base+0x10, base+0x25)   XOR 0xA5 密文        ← 序言 + 填充，加密
  [base+0x25, base+0x4D)   明文窗口岛           ← [ret-0x20, ret+0x28)，含真实 call
  [base+0x4D, ...)          明文                 ← MessageBox 序列 + 字符串
```

窗口的几何完全由检测器的解码范围决定：`TryFindValidDisasm` 读 `[ret-0x20, ret+0x28)`，我们就让这 0x28 字节保持明文；窗口里放一条**真实的** `call StubSleep`——不是假 call，是执行流真的会走的那条。

这个方案的"通用性"边界必须说清楚：它不依赖检测器白名单、call 目标是真实函数（`CalcNextJmpAddress` 验证通过）、栈 walk 自然终止——在**这三个意义上**不是 PoC 缺陷利用。但**窗口几何本身是照 Duck Eye 的采样范围定制的**：检测器换窗口尺寸、或对同一帧采样两个区域，"岛"就会沉进密文里。密文是特征，窗口只是把特征藏到检测器当前不读的地方——这是对"固定采样几何的解码器"的绕过，不是对"解码器类别"的通用。对抗类别唯一的内容层答案是全页合法指令（无密文），那是另一组权衡。

A/B 实验（MSVC + MinGW 双工具链 × 4 组合全矩阵）：

| 模式 | 加密范围 | Duck Eye |
|---|---|---|
| `island`（默认） | `[base, base+0x15)` | **零告警** |
| `-full`（对照） | `[base, base+0x55)`（窗口也加密） | `SleepMask Encryption Memory Detected` |

同一个 payload、同一个睡眠周期、唯一变量是窗口是否加密——检测器的判定完全由这一个变量决定。

## 三、工程实现：把"自修改代码"做进 PE 里

绕过逻辑上成立后，工程上有两个硬约束：**stomp 目标必须长得像正常函数**，**自修改不能留下 API 痕迹**。

**模块 stomp 与 .pdata 一致性。** payload 覆盖 `.pay` 段里的 `StompTarget`：30 个 noinline 调用强制非 leaf 帧，编译器生成的最小序言 `sub rsp, 0x28` 与 .pdata 的 unwind 信息一致。shellcode 在运行时把 imm8 复制到自己身上（`sub rsp,imm8`/`add rsp,imm8` 同步），保证 unwind 解出来和实际栈用量吻合。早期用无 .pdata 的落地缓冲区方案实测无效——dbghelp 回退到 RBP 链会产生垃圾帧，反而误报。

**PIC shellcode 的布局即文档**（0x9D 字节，含字符串）：

```
0x00: sub rsp,0x28         0x2C: mov [rsp+0x20],eax   (记分操作数)
0x26: mov eax,[rip+d]      0x30: call StubSleep       (窗口内的真实调用)
0x35: g_shared.calls++     0x43: lea rdx,[rip+d]      (lpText)
0x4A: lea r8,[rip+d]       (lpCaption)  0x56: mov rax,imm64 MessageBoxA
0x60: call rax             0x68: add rsp,0x28 / ret
0x6D: "SleepMask Bypass Demo"   0x83: "Hello from PIC shellcode"
```

所有 rip-relative 槽位运行时按实际基址重定位；字符串偏移有 strcmp 自检防回归。

**RWX 映像节替代 VirtualProtect。** 早期实现靠 `VirtualProtect` 在 RX↔RWX 之间翻转，后来按"零保护相关 API"的要求重做：`.pay` 在**链接期**声明为 RWX（GCC `__asm__(".section .pay,\"awx\"")`；MSVC `#pragma code_seg` 会强制代码节 RX，需要 `editbin /SECTION:.pay,WE` 后处理）。于是 stomp 是裸 `memcpy`，睡眠加密是原地 XOR——**全程零 VirtualProtect、零 syscall**。gdb 在 `kernel32!VirtualProtect` 下断点跑完整实验：0 次命中。导入表里残留的 VirtualProtect 是 CRT 静态包袱，从未被调用。

进程内存态的实测（睡眠窗口内 `VirtualQueryEx` 枚举全进程）：**唯一一个 RWX 区域就是 `.pay` 那一页**——从加载起就是 RWX，全程零翻转。这是"零 API 自修改代码"的必然形态，也是后文所有检测面讨论的锚点。

## 四、升级威胁模型：Elastic 的 unbacked 语义

Duck Eye 是本地扫描器。真实世界的威胁模型是 EDR，于是把 [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) 拉下来，770 条 Windows 行为规则、254 条引用 `call_stack`、约 100 条涉及 unbacked——逐一对照。

**规则语义的解剖**（以 `Network Module Loaded from Suspicious Unbacked Memory` 为例）：

```
[library where
  dll.name in~ ("ws2_32.dll", "wininet.dll", "winhttp.dll") and   # 事件半边：加载网络模块
  process.thread.Ext.call_stack_contains_unbacked == true and     # 栈半边：帧解析不到映像
  call_stack_summary : "...|kernelbase.dll|Unbacked" ...]
```

Elastic 的栈序列化器给每个帧打标签：解析到已加载映像 → 模块名；解析不到 → `Unbacked`。**检测的判别核心是"帧有没有映像背书"，不是"页是不是 RWX"**——这是整个分析中最关键的一句话。

用 `-walk` 模式在 harness 内部复刻这个分类（`RtlCaptureStackBackTrace` + 逐帧 `VirtualQuery`）：

```
[walk] 00 bypass_mingw.exe+0x17B4  IMAGE RX   backed     (WalkAndClassify)
[walk] 01 bypass_mingw.exe+0xD215  IMAGE RX   backed     (StubSleep, .stb)
[walk] 02 bypass_mingw.exe+0xF045  IMAGE RWX  backed     (shellcode, .pay ← 唯一"异常"帧)
[walk] 03-06 ...                  IMAGE RX   backed     (main/CRT)
[walk] 07 KERNEL32 / 08 ntdll     IMAGE RX   backed
[walk] unbacked_frames=0 → call_stack_contains_unbacked=false (rule silent)
```

注意帧 02：**`EXECUTE_READWRITE` 的映像节帧照样算 `backed`**——Elastic 判定"可疑"的依据是内存类型（`MEM_IMAGE` vs 私有/映射），RWX 与否根本不进判别式。

对照实验把同一个 payload 搬进私有 RWX（`-walkpriv`）：帧 02 立刻变成 `PRIVATE RWX UNBACKED`，`unbacked_frames=1`，规则谓词成立；Duck Eye 同步爆出 5 条检出。**同一份字节，只有内存背书不同，结局完全相反。**

## 五、检测面守恒：三个可执行形态的必然取舍

双映射（一个 section 映射 RW + RX 两个视图）是消除 RWX 页的主流替代。实测后它死在三件事上：

1. `MapViewOfFileEx` 显式基址在本平台全部 `ERROR_INVALID_ADDRESS`（487），RX 视图只能落在堆区；
2. 堆区视图的帧是 `MEM_MAPPED`，按 Elastic 语义同样解析不到映像 = `Unbacked`——**栈归属面输掉**；
3. 即便修好布局，`evasion_via_multiple_memory_section_mapping` 规则盯着映射事件（虽然它要求 RWX 参数，我们恰好避开）。

把三个可执行形态放到六个检测面上（内容一致性 = 内存内容 vs 磁盘映像的比对，module stomping 检测史的主线）：

| 形态 | 静态节特征 | 页属性扫描 | 保护翻转 API | 分配/映射 API | 栈帧归属 | 内容一致性 |
|---|---|---|---|---|---|---|
| `.pay` 映像 RWX（本方案） | RWX 节 ✗ | RWX 页 ✗ | 0 ✓ | 0 ✓ | **IMAGE ✓** | **✗（理论）/ 实测豁免**（见下注） |
| 瞬态翻转（VirtualProtect） | 干净 ✓ | 睡眠时 RX ✓ | VP×N ✗ | 0 ✓ | IMAGE ✓ | ✗（stomp 内容同样不一致） |
| 双映射（RW+RX 视图） | 干净 ✓ | 干净 ✓ | 0 ✓ | 映射事件 ✗ | **MAPPED = Unbacked ✗** | N/A（私有 section 无磁盘基准） |

**结论：栈帧归属只有"映像背书"能赢，而映像背书必然付出 RWX 节/页的代价——且 stomp 形态在"内容一致性"这一列理论上必输。** 这不是实现缺陷，是检测面守恒——可执行内存的三种形态各自在至少一个面上可见，不存在全隐身点。注意"✗（理论）/ 实测豁免"的一格：理论暴露与实现豁免是两层，同一格里都写着。

仓库层面的事实核查（这也是"Elastic 有没有 RWX 页扫描"的答案）：770 条行为规则里 `PAGE_EXECUTE_READWRITE` 字面量**零命中**，`memory_region.protection` 字段**零用法**；27 条含 rwx 的规则全部是三种形态——API 事件伴随检查（VirtualProtect/分配）、Unbacked 限定（私有内存）、排除条款豁免（`process_creation_from_backed_rwx` 用 `*.exe+*` 滤掉带偏移的映像内 RWX 帧）。**行为规则是事件驱动的，没有主动的 RWX 页普查**；YARA 是 670 条家族指纹，认已知样本不认新样本。主动内存扫描是闭源引擎的地盘——那部分不可见，只能推测。

**内容一致性维度（hollows_hunter v0.4.1.1 + pe-sieve v0.4.1.1 独立交叉验证）**。本方案的 `.pay` 磁盘上是 StompTarget（30 个 noinline 调用），运行时被 stomp 成 shellcode——内存与磁盘永远不一致，这是本方案最根本的"内容层"暴露。**地基检查**：island 睡眠窗口内用 `dumpdiff`（见 `tools/`）读目标进程 `.pay` 内存与磁盘文件逐字节比对——**142/192 字节不一致**（磁盘上是 `E8`/`FF` 调用序列，内存里是 shellcode 的 `90` NOP 与 XOR 密文）——以下所有"0 检出"结论的前提（扫描时刻内存≠磁盘）成立。

对照实验（patch 位置是关键变量，排除循环论证）：

| 场景 | patch 位置 | hollows_hunter 默认 | `/threads` | `/hooks` |
|---|---|---|---|---|
| island（.pay stomp + XOR 窗口） | 第二代码节 `.pay`（+0xE000） | 0 | 0 | **0** |
| 私有 RWX shellcode（对照） | — | 0 | **1**（implanted_shc） | — |
| 教科书 stomp A（`patchself`） | `.text+0x50`（入口点 +0x50，static 非导出） | 0 | — | **1** |
| 教科书 stomp B（`patchdeep`） | `.text+0x7670`（首代码节深处） | 0 | — | **1** |
| 教科书 stomp C（`patchext`） | 第二代码节 `.payx`（RX，+0x9000） | 0 | — | **0** |

三个事实：① hollows_hunter **默认不做节内容比对**（教科书 stomp 都放过）；② `/hooks` 通道对**首代码节（.text）任意位置**做 image-vs-disk 比对（A/B 都报，证明覆盖整个节、与导出/入口区无关），但**不覆盖后续代码节**（C 和 island 都 0，与节权限无关——`.payx` 是 RX 同样豁免）——`.pay` 的豁免是"节位置"性的；③ `/obfusc 3` 对映像节内 0x15 字节 XOR 不触发（Moonwalk++ 评估里的检出场景是私有内存的大区域加密）——窗口方案把密文缩到 obfus 粒度之下是意外收益，不是设计。

交叉验证：pe-sieve v0.4.1.1 **独立运行**（`/threads /obfusc 3 /shellc 3 /data 3`）对 island / patchself / walkpriv 三场景结果与 hollows_hunter 对应通道一致（island 0、patchself 0——注意 pe-sieve 独立版没有 `/hooks` 开关，该通道是 hollows_hunter 封装层行为，封装层差异已排除，核心结论不受影响）。所有对照样本与工具在 `tools/` 可复现。

**实现豁免，不是类别免疫**：全量 image-vs-disk 比对（扫所有节）一旦出现，`.pay` 必死——第六列那格"✗（理论）/ 实测豁免"就是这层意思。

## 六、CET 影子栈：控制流真值改变什么

Intel CET 的两个组件（SS 影子栈 / IBT 间接分支跟踪）常被当作堆栈欺骗的终结者。

- **影子栈保存的是调用者的返回地址**，验证 CALL/RET 配对——它区分"链真/链假"，不区分"帧良/帧恶"；
- 本方案的执行链是编译器生成的真实调用（`main → call .pay → call StubSleep`），影子栈对比**完全一致**；
- IBT 只约束间接跳转（目标需 `ENDBR64`），`call rel32` 天然免疫；
- 所以即使 EDR 拿到影子栈真值（`RtlWalkShadowStack` 之类），帧归属检查的结果与常规栈相同：全映像、可归属——**它杀不掉内容层的规避**。

CET 真正根治的是"伪造返回地址"那一类欺骗——而本方案从一开始就不伪造返回地址，把欺骗做在内容层（加密+窗口+stomp）。攻防的演变在这里看得最清楚：检测从"启发式猜"升级到"硬件真值"，攻击就从"骗过启发式"转移到"真值一致但内容可疑"——而内容可疑的判定，又回到了页属性与节特征——即第一节 Duck Eye 就在做的那些检查。

## 七、结论：攻防演变的本质

一次完整的攻防循环下来，三条经验：

1. **检测器的检测面决定绕过的最小形态。** Duck Eye 的三层启发式换来的是"窗口加密"这一个几何答案；Elastic 的 unbacked 语义换来的是"映像背书"这一个架构答案。先读检测逻辑，再谈绕过。
2. **检测面守恒，但面的可见性取决于实现代际。** 消除一个面上的特征，必然在另一个面上留下痕迹。映像背书赢栈归属、输节特征；双映射赢页属性、输栈归属。但 hollows_hunter 的实测展示了另一层：**你选择的不是在哪个面可见，而是在哪个面的哪一代实现上可见**——内容一致性这一列，理论必输，但当前代的开源工具（hollows_hunter 只比首代码节、pe-sieve 默认不比内容）全数豁免；下一代工具（全量节比对）一旦出现，同一列立刻翻转。守恒讲的是"必然在某面可见"，实现代际决定的是"现在在哪一代上可见"。
3. **内容层规避是 CET 时代的幸存者。** 当控制流真值不可伪造，把欺骗做进内容（真实调用链 + 窗口明文 + 可验证的 call）是唯一不与真值冲突的路径；而内容检查的未来，仍是字节、页属性与节特征——也就是这场实验从头到尾都在打的地方。

---

## 复现

```
msbuild StackSpoof.sln -p:Configuration=Release -p:Platform=x64
# 产物：x64/Release/sleep_duck.exe（检测器）、x64/Release/bypass.exe（harness）

sleep_duck.exe -pid <pid>          # 检测器独立运行
bypass.exe                         # 实验组（island，预期零告警）
bypass.exe -full                   # 控制组（预期 SleepMask Encryption Memory Detected）
bypass.exe -walk / -walkpriv       # Elastic 风格栈分类（映像背书 vs 私有内存）
bypass/clicker.ps1                 # 自动点击 MessageBox（SendMessage WM_COMMAND IDOK）
```

MinGW-w64 备选构建：`build_bypass.bat` / `build_mingw.bat` / `build_detector.bat`。

内容一致性实验工具（`tools/`）：`dumpdiff.exe <pid> .pay`（内存 vs 磁盘逐字节比对）、`patchself/patchdeep/patchext`（三个 patch 位置对照样本）、`hh/`（hollows_hunter v0.4.1.1）、`ps/`（pe-sieve v0.4.1.1 独立版）。

**免责声明**：实验与教育用途。检测器为上游开源项目 fork，两处 bug 修复均保留中文披露注释。
