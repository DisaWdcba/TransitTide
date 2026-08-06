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

为什么这是"通用"绕过而不是 PoC 缺陷：

- 不依赖白名单（检测器没有）；
- call 目标是真实函数（`CalcNextJmpAddress` 验证通过）；
- 栈 walk 自然终止（没有伪造的帧终止条件）。

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

把三个可执行形态放到五个检测面上：

| 形态 | 静态节特征 | 页属性扫描 | 保护翻转 API | 分配/映射 API | 栈帧归属 |
|---|---|---|---|---|---|
| `.pay` 映像 RWX（本方案） | RWX 节 ✗ | RWX 页 ✗ | 0 ✓ | 0 ✓ | **IMAGE ✓** |
| 瞬态翻转（VirtualProtect） | 干净 ✓ | 睡眠时 RX ✓ | VP×N ✗ | 0 ✓ | IMAGE ✓ |
| 双映射（RW+RX 视图） | 干净 ✓ | 干净 ✓ | 0 ✓ | 映射事件 ✗ | **MAPPED = Unbacked ✗** |

**结论：栈帧归属只有"映像背书"能赢，而映像背书必然付出 RWX 节/页的代价。** 这不是实现缺陷，是检测面守恒——可执行内存的三种形态各自在至少一个面上可见，不存在全隐身点。

仓库层面的事实核查（这也是"Elastic 有没有 RWX 页扫描"的答案）：770 条行为规则里 `PAGE_EXECUTE_READWRITE` 字面量**零命中**，`memory_region.protection` 字段**零用法**；27 条含 rwx 的规则全部是三种形态——API 事件伴随检查（VirtualProtect/分配）、Unbacked 限定（私有内存）、排除条款豁免（`process_creation_from_backed_rwx` 用 `*.exe+*` 滤掉带偏移的映像内 RWX 帧）。**行为规则是事件驱动的，没有主动的 RWX 页普查**；YARA 是 670 条家族指纹，认已知样本不认新样本。主动内存扫描是闭源引擎的地盘——那部分不可见，只能推测。

## 六、CET 影子栈：控制流真值改变什么

Intel CET 的两个组件（SS 影子栈 / IBT 间接分支跟踪）常被当作堆栈欺骗的终结者。机制层面的推演（本实验环境 i7-5557U + Win10 19045 无 CET 硬件，纯推演）：

- **影子栈保存的是调用者的返回地址**，验证 CALL/RET 配对——它区分"链真/链假"，不区分"帧良/帧恶"；
- 本方案的执行链是编译器生成的真实调用（`main → call .pay → call StubSleep`），影子栈对比**完全一致**；
- IBT 只约束间接跳转（目标需 `ENDBR64`），`call rel32` 天然免疫；
- 所以即使 EDR 拿到影子栈真值（`RtlWalkShadowStack` 之类），帧归属检查的结果与常规栈相同：全映像、可归属——**它杀不掉内容层的规避**。

CET 真正根治的是"伪造返回地址"那一类欺骗——而本方案从一开始就不伪造返回地址，把欺骗做在内容层（加密+窗口+stomp）。攻防的演变在这里看得最清楚：检测从"启发式猜"升级到"硬件真值"，攻击就从"骗过启发式"转移到"真值一致但内容可疑"——而内容可疑的判定，又回到了页属性与节特征——即第一节 Duck Eye 就在做的那些检查。

## 七、结论：攻防演变的本质

一次完整的攻防循环下来，三条经验：

1. **检测器的检测面决定绕过的最小形态。** Duck Eye 的三层启发式换来的是"窗口加密"这一个几何答案；Elastic 的 unbacked 语义换来的是"映像背书"这一个架构答案。先读检测逻辑，再谈绕过。
2. **检测面守恒。** 消除一个面上的特征，必然在另一个面上留下痕迹。映像背书赢栈归属、输节特征；双映射赢页属性、输栈归属。不存在全隐身方案——选择"在哪个面可见"，而不是"是否可见"。
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

**免责声明**：实验与教育用途。检测器为上游开源项目 fork，两处 bug 修复均保留中文披露注释。
