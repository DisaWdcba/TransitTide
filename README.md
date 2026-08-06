# StackSpoof_Exp — 睡眠混淆 / 堆栈欺骗检测对抗实验

对 [huoji120/sleep_duck_eye](https://github.com/huoji120/sleep_duck_eye) 检测器的攻防对照实验。

- **检测器**：`sleep_duck_eye/`（上游 fork，含两处真实 bug 修复，见下文）
- **实验组**：`bypass/` — 单文件 harness，睡眠加密引擎 + 模块 stomp + PIC shellcode，检测器作为子进程独立运行

## 构建

Visual Studio（VS2022/2026 均可，`PlatformToolset` 自适应）：

```
msbuild StackSpoof.sln -p:Configuration=Release -p:Platform=x64
```

产物：`x64/Release/sleep_duck.exe`（检测器，静态链接 capstone）、`x64/Release/bypass.exe`（harness）。

命令行（MinGW-w64 与 MSVC 双工具链）：

```
build_detector.bat    # 检测器 -> sleep_duck.exe（根目录）
build_bypass.bat      # MSVC 版 harness -> bypass/bypass.exe（含 editbin 把 .pay 标记为 RWX）
build_mingw.bat       # MinGW 版 harness -> bypass/bypass_mingw.exe
```

## 用法

检测器独立运行：`sleep_duck.exe`（全系统扫描）或 `sleep_duck.exe -pid <pid>`。

harness 模式（`-full` 控制组预期被检出）：

| 模式 | 说明 | 检测器结果 |
|---|---|---|
| （默认）island | stomp + 睡眠加密 + 保留返回地址窗口明文 | 干净 |
| `-full` | 窗口一并加密（Ekko 式对照） | `SleepMask Encryption Memory Detected` |
| `-walk` | island + 栈帧 Elastic 风格分类 | 干净，`unbacked_frames=0` |
| `-walkpriv` | 载荷搬进私有 RWX（无映像背书对照） | 检出，`unbacked_frames=1` |
| `-walkmap` | 双视图映射（RW+RX，平台限制演示） | — |
| `-idle` / `-scan` / `-msgtest` / `-desktop` | 辅助模式 | — |

自动化：`bypass/clicker.ps1` 自动点击 MessageBox（SendMessage WM_COMMAND IDOK）。

## 方法要点

- **窗口感知加密**：睡眠时加密代码，但保留返回地址前 `[ret-0x20, ret+0x28)` 明文窗口，使检测器的指令解码/调用解析通过；`-full` 把窗口也加密即被检出。
- **RWX 映像节替代 VirtualProtect**：`.pay` 节链接期声明为 RWX（GCC `"awx"` / MSVC `editbin /SECTION:.pay,WE`），stomp 与 XOR 均为裸内存写——全程零 VirtualProtect、零 syscall（gdb 断点 0 命中验证）。
- **检测器修复**（已在上游代码中注释披露）：
  1. `TryFindValidDisasm` 中 `cs_free(insn)` 后立即拷贝 → use-after-free，导致真实 ntdll/kernel32 帧误报；
  2. `StackTracker` 构造器未初始化 `ins_ip/ins_ip_address/readSuccess` → 垃圾帧误报。
- **检测面结论**：全映像背书帧使 Elastic 类 `call_stack_contains_unbacked` 规则不成立；`.pay` 常驻 RWX 映像节是唯一静态可见特征（对节特征扫描器可见，对 API/栈规则不可见）。

## 免责声明

实验/教育用途。检测器为上游开源项目 fork，bug 修复处均保留中文披露注释。
