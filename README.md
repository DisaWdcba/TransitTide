# 从 Duck Eye 到 Elastic：看新兴堆栈攻防的演变

> 一次针对 [sleep_duck_eye](https://github.com/huoji120/sleep_duck_eye) 检测器的完整攻防实验记录——从三层检测机制解剖、通用绕过设计，到 Elastic 规则集的检测面守恒分析，最后推演 CET 影子栈时代的攻防形态。所有结论均来自本仓库可复现的实验。

## 一、起点：Duck Eye 凭什么"通杀"市面堆栈欺骗

鸭哥的 `sleep_duck_eye`（下文称 Duck Eye）是一个扫进程内存的检测器，专抓睡眠混淆和堆栈欺骗。它的检测逻辑分三层，开销和复杂度逐层递增。

第一层是帧属性检查（`SimpleCheckIn2020`）：对栈上每个帧地址做 `VirtualQuery`，是 `MEM_IMAGE`（有映像背书）就短路放行，不是就查页保护，私有 RWX 直接算可疑。这是最朴素的一层——shellcode 通常住在 `VirtualAlloc` 出来的私有内存里，解析不到任何模块。所以 `MEM_IMAGE` 就是它的盲区开关：帧只要属于某个已加载的 PE，这一层直接放行。

第二层是指令流启发式（`TryFindValidDisasm`）：读返回地址往前 0x20 字节开始的 0x28 字节，也就是 `[ret-0x20, ret+0x08)`，扔给 capstone 反汇编打分。能解出像样的指令序列就过，解不出来（密文、垃圾字节）就报 "Non-integrity"。这层明显是冲着 Ekko 类方案来的——睡眠时整个代码页加密，返回地址正好指着密文，解码必挂。

第三层是 call 目标解析（`CalcNextJmpAddress`）：在窗口里找 call 指令，不管是 RIP 相对、寄存器还是内存间接，都真正算出目标地址再验证。有的绕过方案会在窗口里摆一条指向 Sleep 的假 call 做掩护，这层就是识别这类伪装的。

读代码时顺手修了两个真实的 bug：

1. `TryFindValidDisasm` 里 `cs_free(this->insn)` 之后马上又去拷贝 `insList`——use-after-free，反汇编结果被毁，导致真实的 ntdll/kernel32 帧大面积误报；
2. `StackTracker` 构造器没初始化 `ins_ip/ins_ip_address/readSuccess`——垃圾字段让 `getNextIns()` 直接返回 nullptr，**每个被扫的帧看起来都像 Non-integrity**。

修复前扫一个 notepad 都会满屏告警，修复后干净。这说明所谓"通杀"建立在一堆脆弱启发式之上，而启发式本身就留有绕过空间。

## 二、绕过设计：全量加密的死，与窗口加密的生

经典睡眠混淆（Ekko 式）睡眠时把整个代码页加密。先拿它当对照组喂给 Duck Eye，结果干净利落：

```
SleepMask Encryption Memory Detected: <base+0x20>
```

第二层解码直接失败。注意这里检测器根本不需要知道密钥——它只需要发现"返回地址附近的字节不是合法指令"。**加密这件事本身就是特征。**

反过来：如果加密时专门把检测器要读的那段窗口留出来呢？

```
睡眠时 .pay 页里的字节态（检测器扫描的那一刻）：
  [base,      base+0x20)   XOR 0xA5 密文     ← 序言 + 填充，加密
  [base+0x20, base+0x48)   明文窗口          ← [ret-0x20, ret+0x08)，含真实 call
  [base+0x48, ...)          明文             ← stdio 序列 + 指针表 + marker
```

窗口几何完全由检测器的采样范围决定：它读 `[ret-0x20, ret+0x08)` 这 0x28 字节，我们就让这 0x28 字节保持明文；`call StubSleep` 的返回地址落在 `base+0x40`，窗口 `[base+0x20, base+0x48)` 正好包住它——不是伪装 call，而是执行流实际会走的那条。

通用性的边界需要说清楚：这方案不依赖检测器白名单，call 目标是真实函数（第三层验证照样过），栈回溯自然终止——在这三个意义上不算 PoC 缺陷利用。但窗口几何是照 Duck Eye 的采样范围裁剪的，检测器若扩大窗口、偏移采样点，或对同一帧采多个区域，这块明文"岛"就会沉进密文。密文是特征，窗口只是把特征挪到检测器当前不读的位置——绕过的是"固定采样几何的解码器"，不是"解码器"这个类别。若要对类别免疫，内容层唯一的答案是全页都是合法指令（无密文），那是另一组权衡。

A/B 实验（MSVC + MinGW 双工具链 × 4 组合全矩阵）：

| 模式 | 加密范围 | Duck Eye |
|---|---|---|
| `island`（默认） | `[base, base+0x20)` | **零告警** |
| `-full`（对照） | `[base, base+0x60)`（窗口也加密） | `SleepMask Encryption Memory Detected` |

同一个 payload、同一个睡眠周期，唯一变量是窗口是否加密——检测结果完全跟随这一变量。

## 三、工程实现：把"自修改代码"做进 PE 里

逻辑上成立之后，工程上有两个硬约束：stomp 目标得长得像正常函数，自修改不能留下 API 痕迹。

**模块 stomp 与 .pdata 一致性。** payload 覆盖 `.pay` 段里的 `StompTarget`：30 个 noinline 调用强制它成为非 leaf 帧，编译器生成的最小序言 `sub rsp, 0x28` 跟 .pdata 的 unwind 信息一致。shellcode 运行时把这个 imm8 复制到自己身上（`sub rsp,imm8` / `add rsp,imm8` 同步），保证 unwind 解出来的栈用量和实际一致。早期试过用没有 .pdata 的落地缓冲区，实测不行——dbghelp 回退到 RBP 链会产生垃圾帧，反而误报。

**PIC shellcode 的布局即文档**（0xB3 字节，含指针表与 marker）：

```
0x00: sub rsp,0x28                         0x30: mov [rsp+0x20],eax   (记分操作数)
0x34: lea rax,[rip+d] -> &tbl.stub        0x3B: mov rax,[rax]
0x3E: call rax                             0x40: g_shared.calls++     (ret = 0x40)
0x4F: lea rax,[rip+d] -> &tbl.gsh         0x56: mov rax,[rax]
0x5E: call GetStdHandle(STD_OUTPUT_HANDLE) 0x63: lea rax,[rip+d] -> &tbl.wf
0x6A: mov rax,[rax]                        0x6D: lea rdx,[rip+d] -> marker
0x74: mov r8d,3                            0x88: call WriteFile
0x8A: add rsp,0x28 / ret                   0x8F: "OK\n"
0x93: tbl.g_shared  0x9B: tbl.gsh  0xA3: tbl.wf  0xAB: tbl.stub
```

新版本放弃 imm64 常量和 UI API，改成 view-local 指针表 + `GetStdHandle`/`WriteFile` 的纯 stdio 路径：所有函数地址和 `g_shared` 指针都塞进 `.pay` 末尾的表里，运行时重定位；执行时从表里取值再 call，看起来像 vtable 调用。`"OK\n"` marker 同时作为行为完成的自检标记。

**RWX 映像节替代 VirtualProtect。** 最早的实现靠 `VirtualProtect` 在 RX 与 RWX 之间反复切换，这会引起一些主流 EDR 的告警——切换内存属性是高危检测面。改进思路：`.pay` 在**链接期**就声明成 RWX（GCC 是 `__asm__(".section .pay,\"awx\"")`；MSVC 的 `#pragma code_seg` 会强制代码节 RX，得 `editbin /SECTION:.pay,WE` 后处理）。这样 stomp 就是裸 `memcpy`，睡眠加密是原地 XOR——全程零 VirtualProtect、零 syscall。在 gdb 里给 `kernel32!VirtualProtect` 下断点跑完整实验：命中 0 次。导入表里残留的 VirtualProtect 是 CRT 的静态依赖，从未被调用。

睡眠窗口内用 `VirtualQueryEx` 枚举全进程内存，实测下来**唯一的 RWX 区域就是 `.pay` 那一页**——从加载起就是 RWX，全程零翻转。这是"零 API 自修改"的必然形态，也是后面所有检测面讨论的锚点。

**内容还原（默认 island 模式）——对抗内存区域特征型 EDR。** 针对"映像内非 .text 节 + RWX 页 + 内容可反汇编出 shellcode"这类检测（实测告警直接抓到 `.pay` 页里的 payload 字节），island 模式在睡眠时不再只加密前缀，而是把 `.pay` **整体还原成磁盘原始内容**（stomp 前保存的 StompTarget 镜像，30 个 call 的正常函数形态），唤醒后再重新 stomp 回去：

```
睡眠前：memcpy(.pay, g_pristinePay)    ← 页内容 == 磁盘内容（反汇编特征消失）
睡眠中：image-vs-disk 比对通过          ← 第五节表格里"理论必输"那格翻转为实测通过
唤醒后：memcpy(.pay, g_shellcodeCopy)  ← 恢复 payload，继续执行
```

验证（MSVC + MinGW 双工具链）：island 还原模式 Duck Eye 零告警、`restored pristine OK` 自检通过、`OK\n` marker 正常写出；full 控制组（保留 XOR 路径）依旧被检出。代价：RWX 页属性与节位置特征仍在（若 EDR 单独凭页保护判定则无效），唤醒窗口（stomp→执行）的内容与磁盘不一致，持续时间微秒级。

## 四、升级威胁模型：Elastic 的 unbacked 语义

Duck Eye 只是本地扫描器，真实环境的对手是 EDR。于是把 [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) 拉下来审计了一遍：770 条 Windows 行为规则，254 条引用 `call_stack`，约 100 条涉及 unbacked。

以 `Network Module Loaded from Suspicious Unbacked Memory` 为例解剖规则语义：

```
[library where
  dll.name in~ ("ws2_32.dll", "wininet.dll", "winhttp.dll") and   # 事件半边：加载网络模块
  process.thread.Ext.call_stack_contains_unbacked == true and     # 栈半边：帧解析不到映像
  call_stack_summary : "...|kernelbase.dll|Unbacked" ...]
```

Elastic 的栈序列化器给每个帧打标签：能解析到已加载映像就写模块名，解析不到就写 `Unbacked`。所以**判别的核心是"帧有没有映像背书"，不是"页是不是 RWX"**——整篇分析里最关键的就是这一句。

用 `-walk` 模式在 harness 内部复现这个分类（`RtlCaptureStackBackTrace` + 逐帧 `VirtualQuery`）：

```
[walk] 00 bypass_mingw.exe+0x17B4  IMAGE RX   backed     (WalkAndClassify)
[walk] 01 bypass_mingw.exe+0xD215  IMAGE RX   backed     (StubSleep, .stb)
[walk] 02 bypass_mingw.exe+0xF045  IMAGE RWX  backed     (shellcode, .pay ← 唯一"异常"帧)
[walk] 03-06 ...                  IMAGE RX   backed     (main/CRT)
[walk] 07 KERNEL32 / 08 ntdll     IMAGE RX   backed
[walk] unbacked_frames=0 → call_stack_contains_unbacked=false (rule silent)
```

注意帧 02：**RWX 的映像节帧照样算 `backed`**——Elastic 判可疑看的是内存类型（`MEM_IMAGE` vs 私有/映射），RWX 与否根本不进判别式。

对照实验把同一个 payload 搬进私有 RWX（`-walkpriv`）：帧 02 立刻变成 `PRIVATE RWX UNBACKED`，`unbacked_frames=1`，规则谓词成立，Duck Eye 同步报出 5 条检出。同一份字节，只有内存背书不同，结局完全相反。

## 五、检测面守恒：三个可执行形态的必然取舍

双映射（一个 section 映射出 RW + RX 两个视图）是消除 RWX 页的主流替代方案，实测下来问题出在三处：`MapViewOfFileEx` 显式基址在本平台全部 `ERROR_INVALID_ADDRESS`（487），RX 视图只能落在堆区；堆区视图的帧是 `MEM_MAPPED`，按 Elastic 语义同样解析不到映像，等于 `Unbacked`，栈归属面直接输掉；就算布局修好了，`evasion_via_multiple_memory_section_mapping` 规则还盯着映射事件（虽然它要求 RWX 参数，恰好避开了）。

把三个可执行形态放到六个检测面上看（内容一致性 = 内存内容 vs 磁盘映像的比对，module stomping 检测史的主线）：

| 形态 | 静态节特征 | 页属性扫描 | 保护翻转 API | 分配/映射 API | 栈帧归属 | 内容一致性 |
|---|---|---|---|---|---|---|
| `.pay` 映像 RWX（本方案） | RWX 节 ✗ | RWX 页 ✗ | 0 ✓ | 0 ✓ | **IMAGE ✓** | **✗（理论）/ 实测豁免**（见下） |
| 瞬态翻转（VirtualProtect） | 干净 ✓ | 睡眠时 RX ✓ | VP×N ✗ | 0 ✓ | IMAGE ✓ | ✗（stomp 内容同样不一致） |
| 双映射（RW+RX 视图） | 干净 ✓ | 干净 ✓ | 0 ✓ | 映射事件 ✗ | **MAPPED = Unbacked ✗** | N/A（私有 section 无磁盘基准） |

结论很直接：**栈帧归属只有"映像背书"能赢，而映像背书必然要付出 RWX 节/页的代价；stomp 形态在内容一致性这一列理论上也必输。** 这不是实现缺陷，而是检测面守恒——三种可执行内存形态各自至少在一个面上暴露，不存在全隐身的点。注意"✗（理论）/ 实测豁免"那一格：理论暴露和实现豁免是两层事，都写在同一格里。

顺便回答"Elastic 到底有没有 RWX 页扫描"：770 条行为规则里 `PAGE_EXECUTE_READWRITE` 字面量**零命中**，`memory_region.protection` 字段**零用法**；27 条含 rwx 的规则全是三种形态——API 事件伴随检查（VirtualProtect/分配）、Unbacked 限定（私有内存）、排除条款豁免（`process_creation_from_backed_rwx` 用 `*.exe+*` 滤掉带偏移的映像内 RWX 帧）。行为规则是事件驱动的，没有主动的 RWX 页普查；YARA 那 670 条是家族指纹，认已知样本不认新样本。主动内存扫描是闭源引擎的地盘，那部分看不见，只能推测。

**内容一致性维度（hollows_hunter v0.4.1.1 + pe-sieve v0.4.1.1 独立交叉验证）。** 本方案的 `.pay` 在磁盘上是 StompTarget（30 个 noinline 调用），运行时被 stomp 成 shellcode——内存和磁盘永远不一致，这是本方案最根本的内容层暴露。先做地基检查：island 睡眠窗口内用 `dumpdiff`（`tools/` 下）读取目标进程 `.pay` 内存与磁盘文件逐字节比对，**142/192 字节不一致**（磁盘上是 `E8`/`FF` 调用序列，内存里是 shellcode 的 `90` NOP 和 XOR 密文）——后面所有"0 检出"的前提（扫描时刻内存≠磁盘）成立。

对照实验，patch 位置是关键变量（为了排除循环论证）：

| 场景 | patch 位置 | hollows_hunter 默认 | `/threads` | `/hooks` |
|---|---|---|---|---|
| island（.pay stomp + XOR 窗口） | 第二代码节 `.pay`（+0xE000） | 0 | 0 | **0** |
| 私有 RWX shellcode（对照） | — | 0 | **1**（implanted_shc） | — |
| 教科书 stomp A（`patchself`） | `.text+0x50`（入口点 +0x50，static 非导出） | 0 | — | **1** |
| 教科书 stomp B（`patchdeep`） | `.text+0x7670`（首代码节深处） | 0 | — | **1** |
| 教科书 stomp C（`patchext`） | 第二代码节 `.payx`（RX，+0x9000） | 0 | — | **0** |

三个事实：

1. hollows_hunter **默认不做节内容比对**，教科书 stomp 都放过了；
2. `/hooks` 通道对**首代码节（.text）任意位置**做 image-vs-disk 比对——A、B 都报，说明覆盖整个节，跟导出表、入口区无关——但**不覆盖后续代码节**：C 和 island 都是 0，跟节权限无关（`.payx` 是 RX 照样豁免）。`.pay` 的豁免是"节位置"性的；
3. `/obfusc 3` 对映像节内 0x15 字节的 XOR 不触发——Moonwalk++ 评估里那些检出场景都是私有内存的大区域加密。窗口方案把密文缩到 obfus 粒度之下，属于意外收益，不是设计目标。

交叉验证：pe-sieve v0.4.1.1 **独立运行**（`/threads /obfusc 3 /shellc 3 /data 3`），对 island / patchself / walkpriv 三个场景的结果跟 hollows_hunter 对应通道一致（island 0、patchself 0——注意 pe-sieve 独立版没有 `/hooks` 开关，那个通道是 hollows_hunter 封装层的行为，封装层差异已排除，核心结论不受影响）。所有对照样本和工具都在 `tools/`，可复现。

一句话总结：**这是实现豁免，不是类别免疫。** 全量 image-vs-disk 比对（覆盖所有节）一旦出现，`.pay` 必死。表格里"✗（理论）/ 实测豁免"那格就是这个意思。

## 六、CET 影子栈：控制流真值改变什么

Intel CET 的两个组件（SS 影子栈 / IBT 间接分支跟踪）经常被当成堆栈欺骗的终结者，值得认真推演一下：

- 影子栈保存的是**调用者的返回地址**，验证 CALL/RET 配对。它区分"链真/链假"，不区分"帧良/帧恶"；
- 本方案的执行链是编译器生成的真实调用（`main → call .pay → call StubSleep`），影子栈对比完全一致；
- IBT 只约束间接跳转（目标需要 `ENDBR64`），`call rel32` 天然免疫；
- 所以就算 EDR 拿到了影子栈真值（`RtlWalkShadowStack` 之类），帧归属检查的结果跟常规栈一样：全映像、可归属——**它杀不掉内容层的规避**。

CET 真正根治的是"伪造返回地址"那一类欺骗，而本方案从一开始就没有伪造返回地址，欺骗全做在内容层（加密 + 窗口 + stomp）。攻防演变在这里看得很清楚：检测从"启发式猜测"升级到"硬件真值"，攻击就从"骗过启发式"转移到"真值一致但内容可疑"；而内容可疑的判定，最终又回到页属性和节特征——正是第一节 Duck Eye 就在检查的东西。

## 七、对抗某前沿 EDR：告警 = 事件半边 × 状态半边

推演之外，真实世界总会给出新东西。拿这套方案去碰了一台装了前沿国产 EDR 的机器，四份告警逐步还原出它的检测管线，也修正了我之前的两个判断。这一节的每一条结论都有对应的实测记录。

**四份告警还原出的管线（细节从略）。** 从告警形态看，检测是事件触发型的：敏感模块加载事件 → 对目标进程可执行区域做枚举与内容采样 → 判据锚定在"非标准可执行区域的存在性 + 内容可反汇编"。同一份 payload，四种形态的结果：

| 版本 | Duck Eye | hollows_hunter | 该 EDR |
|---|---|---|---|
| 内容还原（island） | 0 | 0 | 抓（内容采样命中 .pay 区域） |
| 双映射 | 0 | 0 | 抓（无模块背书的映射视图） |
| +形态伪装（零 imm64、vtable 风格） | 0 | 0 | 抓，**无降级** |
| +无 UI 行为 | 0 | 0 | **零告警** |

前三轮都在"状态"层面做优化：内容还原、换内存形态、改指令风格——全部无效，因为判据锚定的是"非 .text 可执行区域的**存在性**"，与内容形态无关。形态伪装那轮（lea/vtable 风格、消除全部 imm64）所有回归测试通过，但告警数量没有下降，是整场实验代价最大的一次无效尝试。

**拆开看告警的乘法结构。** 告警 = 事件半边 × 状态半边：

- **状态半边**：进程里存在"可执行但非 .text 的区域"（私有 RX / MEM_MAPPED 视图 / 映像非代码节）——这是执行自定义代码的必然代价，**不可消**；
- **事件半边**：网络相关系统模块加载触发扫描——**可消**。

关键发现是事件半边的来源：UI 行为会经系统文本服务框架触发网络相关系统模块的加载，这个加载事件触发了扫描，状态半边才被"点名"。告警等级也验证了这一结构：有事件指向的告警级别更高，纯状态判定的级别更低；事件被移除后，只剩下低级别判定，最终也消失了。

**第四层：换行为，不换内存。** 无 UI 化 payload：去掉 MessageBox，改用 `GetStdHandle(STD_OUTPUT_HANDLE)` + `WriteFile("OK\n")`——纯 kernel32、零窗口、零 TSF、零输入法链。UI 行为不是"附加特征"，而是触发扫描的关键路径。调试这版时还修复了一个 bug：hStdOut 曾存到 `[rsp+0x28]`，而 `sub rsp,0x28` 帧里那个槽正好是返回地址位置，ret 直接跳进句柄值 0x730 导致崩溃（gdb 崩溃栈第一帧就是 0x730）。

**规则库审计：零事件面 vs 事件全排除。** 拿 Elastic 770 条行为规则逐条对照三个模式。先盘事件面：`CreateFileMappingW`、`SleepEx`、`GetStdHandle`、`WriteFile`、`GetProcAddress` 全部**不在 ETW Threat-Intelligence provider 的 API 集里**——连事件都不会产生；唯一产生 api 事件的是 `MapViewOfFile×2`。37 条引用 MapViewOfFile 的规则逐条排除：

| 排除依据 | 规则数 | 本方案为何豁免 |
|---|---|---|
| `parameters.protection == "RWX"` | 7 | 视图是 RX（`FILE_MAP_READ\|FILE_MAP_EXECUTE`） |
| `behaviors == "cross-process"` | 5 | 同进程映射 |
| `call_stack_final_user_module == "Unbacked"` | 6 | 调用方是 bypass.exe 模块 |
| `size == 0`（整文件映射） | 2 | 传 0x2000 |
| 特定宿主（msiexec/svchost/wscript…） | 8 | 都不是 |
| syscall/行为标记 | 3 | 走 kernelbase 转发；`NtMapViewOfSection` 在排除表 |
| ROP/回调/定时器栈特征 | 3 | 无 |

一个有意思的边角：`CreateFileMappingW(PAGE_EXECUTE_READWRITE)` 创建的是 RWX **section**，但规则库对 CreateFileMapping **零引用**——只盯 MapViewOfFile 的视图保护。"RWX section + RX 视图"的组合恰好卡在盲区里。同理，`call_stack_contains_unbacked` 对双映射视图确实为真（执行帧解析不到映像），但 12 条用这个谓词的规则全部要求额外事件（进程创建/网络模块/lsass/conhost）——**unbacked 是真值，但没有规则聚合它**。我之前认为"规则会匹配"，结论是错的：谓词为真和规则命中是两回事。

两条隐身路径由此分明：island/full 是**零事件面**（映像节执行，没有任何被监控 API 事件），walkmap 是**事件全排除**（事件存在，但每条规则的附加条件都被属性排除）。二者都不是原理级绕过，而是规则集盲区；一旦 Elastic 增加一条"unbacked 帧上执行 + 任意 I/O"的通用规则，walkmap 就会重新命中。

**误报的观察：为什么真实 EDR 要事件触发才扫描。** 双映射版本在 Duck Eye 下会报几条"SleepMask Encryption Memory Detected"——全是误报：非映像区执行导致 StackWalk64 跨进程展开失败（x64 无 .pdata 时退化为"栈顶值当返回地址"），产生垃圾帧；Duck Eye 对每个回溯帧做滑动评分，连 kernel32 的转发 thunk（`jmp [rip+…]` + int3 填充）都判"加密"。MSVC 构建（有 PDB）同样误报——与符号无关，是"非映像区执行"的固有代价。我曾考虑用 `RtlInstallFunctionTableCallback` 给视图注册展开表，但动态函数表是进程级的，跨进程扫描读不到。**这个误报案例本身就是"事件×状态"设计的注脚**：纯状态扫描器的误报率高到无法实用，真实 EDR 宁可等事件触发再查状态，也不做无差别普查。

## 八、未来展望

顺着检测面守恒往前看，攻防双方下一步大概率会落在下面几个方向上。

**检测侧：全量内容比对。** hollows_hunter 只比首代码节、pe-sieve 默认不比内容，这些都是当前代实现的取舍，不是原理限制。把 image-vs-disk 比对推广到所有代码节，工程上没有本质障碍，代价是性能和误报调优。一旦主流工具迈出这一步，`.pay` 这类 stomp 方案的"实测豁免"就会到期——检测面守恒表格里"✗（理论）"那一格会从备注变成正文。

**响应比扫描更有前途。** 行为规则是事件驱动的，天然看不到"此刻内存里有什么"。但影子栈这类硬件真值给了检测侧一个新选择：不必再猜链真不真，而是直接拿到真值。未来 EDR 的栈检查可能不再是"扫描器定时普查"，而是"事件触发时对照硬件真值"——普查的活交给 CET，扫描器只负责内容层。

**攻击侧：被挤进内容层深水区。** 链伪造被硬件终结、映像背书被内容比对追认之后，剩下的空间只有一个：让内存里的字节在扫描时刻看起来和磁盘上一致，或者干脆无可挑剔。全页合法指令（无密文）、基于 gadget 的执行、把载荷做成数据而非代码——这些方向的共同点是放弃"藏起来"，改走"看起来本来就正常"。窗口加密只是这个转向的第一步，而且是比较粗糙的一步。

**最不确定的变量：性能预算。** 内容比对、逐节哈希、内存页普查，这些检测手段不是做不到，是贵。攻防的边界最后很可能不由检测原理决定，而由厂商愿意为每台终端付出多少 CPU 和 IO 决定。谁能把内容一致性检查做进低开销的常规路径，谁就能把这场实验里 `.pay` 活下来的窗口真正关上。

在此之前，检测面守恒依然成立：每一代实现都会漏掉某个面，而实验的价值就在于提前把它找出来。

---

## 复现

```
msbuild TransitTide.sln -p:Configuration=Release -p:Platform=x64
# 产物：x64/Release/sleep_duck.exe（检测器）、x64/Release/bypass.exe（harness）

sleep_duck.exe -pid <pid>          # 检测器独立运行
bypass.exe                         # 实验组（island，默认内容还原，预期零告警）
bypass.exe -full                   # 控制组（预期 SleepMask Encryption Memory Detected）
bypass.exe -walk / -walkpriv / -walkmap   # Elastic 风格栈分类（映像背书 vs 私有内存 vs 双映射视图）
bypass.exe -msgtest                # 诊断：直接弹一次 MessageBox
bypass/clicker.ps1                 # 仅 -msgtest 调试时自动点击 MessageBox
```

MinGW-w64 备选构建：`bypass/build_bypass.bat`、`bypass/build_mingw.bat`、`build_detector.bat`。

内容一致性实验工具（`tools/`）：`dumpdiff.exe <pid> .pay`（内存 vs 磁盘逐字节比对）、`patchself/patchdeep/patchext`（三个 patch 位置对照样本）、`hh/`（hollows_hunter v0.4.1.1）、`ps/`（pe-sieve v0.4.1.1 独立版）。

**免责声明**：实验与教育用途。检测器为上游开源项目 fork，两处 bug 修复均保留中文披露注释。
