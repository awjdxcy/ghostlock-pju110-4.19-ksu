# PJU110 越狱套件 —— KernelSU 32715 / UAPI 6 on kernel 4.19.191

一条命令，把 PJU110 从普通 shell 抬到 KernelSU root。全程不需要 PC。

只在自己有处置权的设备上使用。不写分区、不装持久化组件，重启即归零。

## 事实表

| 项 | 值 |
|---|---|
| 设备 | PJU110 / MT6833 / arm64 |
| 内核 | `4.19.191+ SMP preempt mod_unload modversions aarch64` |
| 系统 | Android 14，初始 SELinux `enforcing` |
| 底座 | 内核任意地址 8 字节零写（`rt_mutex` 等待者栈上的 UAF） |
| 上装 | 自编 KernelSU 模块，**32715 / UAPI 6** |
| 入口 | `sh /data/local/tmp/ksu`（单文件自包含，5,709,338 B，md5 `8b089395cc0368ed84f2bf9cbcb7388b`） |
| 一次耗时 | **≈ 11 s** |
| 收尾 | 模块 `Live`，SELinux 自动恢复 `enforce=1` |

## 用法

```sh
adb push main/ksu /data/local/tmp/ksu
adb shell chmod 755 /data/local/tmp/ksu
adb shell sh /data/local/tmp/ksu
```

没有 PC 也一样：把 `main/ksu` 拷到手机任意位置，在终端 App 里 `chmod 755` 后 `sh` 它。
脚本自己会切到 `/data/local/tmp` 干活，文件放在哪儿跑都一样；跑完的临时目录和载荷也会清掉。

想先看状态再决定跑不跑，用 `sh ksu check`；它只读，不改任何东西。

## 全程单机

这个项目没有 PC 参与：内核树、交叉编译、反汇编定址、载荷打包、真机调试，全部在手机上完成。
不是“顺便用手机跑了一下”，是本来就只有那台设备可用。

| 环节 | 常规做法 | 这里的做法 |
|---|---|---|
| 内核树 | PC 拉 1.4 GB vendor 源码 | 手机内 `~/ksu/kern`（Ubuntu proot） |
| 交叉编译 | PC 上装 LLVM 工具链 | proot 里的 `clang` / `ld.lld`，`M=` 外部模块构建 |
| 栈偏移定址 | IDA / Ghidra 图形分析 | `llvm-objdump` + 立即数逐个对，`vmlinux` 反汇编 |
| 载荷打包 | PC 上 `tar czf` 拼偏移 | 手机内按 `PAYLOAD_OFFSET` 拆包重拼 |
| 崩溃定位 | PC 接串口 / adb 抓 dmesg | `/proc/last_kmsg`、手抄 panic 栈、寄存器值逐个比对 |

单机带来的限制是真的限制：没有第二块屏幕看反汇编、没有串口看早期日志、每炸一次要等设备
重新起来才能继续。所以下面每一条“坑”都是拿重启换来的。

## 验收（四条都要满足）

```sh
# 1) 模块在跑
cat /proc/modules | grep kernelsu
#    → kernelsu 184320 0 - Live 0xffffffa1……(OE)

# 2) 收尾把 SELinux 写回了严格模式
cat /sys/fs/selinux/enforce
#    → 1

# 3) 模块节点存在
ls -d /sys/module/kernelsu
#    → /sys/module/kernelsu

# 4) 管理器侧
#    版本显示 32715 / UAPI 6，且没有「需要更新内核」提示
```

## 运行时会发生的五件事

1. **选槽位**：按当前状态决定做几步 —— 只关 SELinux、只关模块强签、还是直接走 `cred` 提权。
2. **关 SELinux**：把 `selinux_state.enforcing` 字节清零，进程进入 Permissive 窗口。
3. **提权**：写 `cap_effective / cap_permitted / cap_inheritable`，然后 `setgid` → `setgroups` → `setuid(0)` → `exec`。
4. **上装**：提权后的进程读 `/sdcard/Download/ksu_raw.ko`，用侧信道算出 KASLR slide，
   然后 `init_module(ko, size, "kln=0x… level=3")` —— 符号地址走模块参数，不靠二进制补丁。
5. **收尾**：模块注册 supercall / kprobe、装上 ksud、把 `enforcing` 写回 `1`。

第 3 步会留下一个 `uid=0` 的常驻进程，这是链路的正常产物，不是残留 —— 见下面的红线。

## 耗时与稳定性

| 项 | 观察值 |
|---|---|
| 冷启动后首次完整跑 | **11 s**（端到端） |
| 重复跑 | 稳定落在 11 s 附近 |
| 设备连续运行 | 37,003 s（≈10.3 h），期间模块保持 `Live`、`enforce` 恒为 `1` |

11 秒是端到端：选槽位 → 关 SELinux → 提权 → 上装 → 收尾。同一台设备、同一个脚本重复跑，落在 11 s 附近。
测量要等系统稳定后再开始，开机初期有时钟跳变，早期测出来的数字不可信。

## 红线

| 动作 | 后果 |
|---|---|
| 杀掉那个 `uid=0` 常驻进程 | `init_cred` 引用计数归零 → 内核 panic → 硬重启 |
| 在 Permissive 窗口内做别的事 | 检测逻辑可能在 syscall 出口重读 `uid`，判定“被提权”后杀整个进程组 |
| 期望重启后还在 | 一定会没：模块卸载、`/sys/module/kernelsu` 消失、`enforce` 回 `1` |
| 拿这份 `ksu` 跑别的机型 | 栈偏移是按本机 `vmlinux` 逐条对出来的，换内核必崩 |

`reap` / `clean_stale` 这类清理只处理 `uid!=0` 的进程，`uid=0` 那个永远不碰。写脚本时守这一条。

## 做不到的

- **通不过别的内核**：模块 vermagic 绑死 `4.19.191+`，`gl` 里 49 处内核地址和槽位偏移绑死这台机器的 `vmlinux`。
  换机型能复用的是方法，不是数值 —— 要重算哪些、怎么验，`docs/05-port-to-another-device.md` 有完整清单。
- **`ksu_raw.ko` 没 strip**：4,697,872 B 里约 4.4 MB 是 `.debug_*`。strip 完约 292 KB，也能加载，
  但那就不是本机验证过的那一份了 —— 换模块等于重来一遍验证（还要再踩一次重启）。详见 `bin/README.md`。
- **UAPI 6 的 `LOOKUP_SYMBOLS` 属于可选项**：本机 4.19 没有 `kallsyms_on_each_symbol`，走的是模块内
  既有的跳板逐名解析。拿不到时 ksud 会退回读 `/proc/kallsyms`，不影响启动。
- **`PREINIT` 不置位**：模块是在系统起来之后注入的，看不到 PID 1 的 `selinux_setup`，所以 preinit
  这一档判定为不支持。管理器会正确识别，不触发 `requiresNewKernel`。

## 文件

```
main/
  ksu.sh                控制器全文，469 行 shell —— 想看逻辑直接读这个
  ksu                   单文件一键，尾部载荷 gzip+tar（前 17572 字节 == ksu.sh）
  README_ONDEVICE.md    设备端全流程：槽位、判据、收尾细节
src/
  gl/                   栈喷射源码（含 BUILD.md）
  ksu/                  KernelSU 4.19 适配源码（kernel + uapi，含 BUILD.md）
bin/
  README.md             预编译件清单与 md5
config/
  pju110_4.19.191.config 从本机 /proc/config.gz 原样导出，6211 行
tools/
  pack.sh               从 ksu.sh + 四件从零组装出一个 ksu
  unpack.sh             按脚本里的 PAYLOAD_OFFSET 切出四件并核对 md5
  repack.sh             换掉其中一件再拼回去，头部逐字节不变
  verify.sh             核对可读副本同步、头部长度、shell 语法、四件 md5
docs/
  01-x18-register-panic.md           一次真机 panic 的完整定位与修法
  02-uapi6-lookup-symbols.md         4.19 上补 UAPI6 新超调用
  03-self-contained-payload.md       单文件脚本重打包的偏移约束
  04-load-baseline-and-rollback.md   耗时基线、判据、回滚
  05-port-to-another-device.md       换机型：要重算哪些常量、按什么顺序验证
```

载荷四件（解开 `ksu` 尾部即为这四份）：

| 文件 | 大小 | md5 |
|---|---|---|
| `lt/gl_v112` | 870,760 | `2c4717dc596daca084f7317250fc8765` |
| `dl/ksu_raw.ko` | 4,697,872 | `44608d0d3fa8777304a6be1af069ecb9` |
| `dl/libksud.so` | 4,990,848 | `b7b87ee9dc0e57a393a28d88055e06fa` |
| `dl/allowlist.bin` | 792 | `c4221d6f192bebe8639223513cf7ac00` |

## 深入阅读

| 想看什么 | 去哪 |
|---|---|
| 控制器那 469 行到底怎么判定的（不用解包，直接读） | `main/ksu.sh` |
| 设备端完整流程与收尾动作 | `main/README_ONDEVICE.md` |
| 那次 panic：`ldr x3,[x18]`、x18=`0xb538`、`ksu54_resolve_all+0xbc` | `docs/01-x18-register-panic.md` |
| 4.19 上怎么把 UAPI6 的 `LOOKUP_SYMBOLS` 补上 | `docs/02-uapi6-lookup-symbols.md` |
| 为什么只替换外部 `ksu_raw.ko` 不生效 | `docs/03-self-contained-payload.md` |
| 耗时、判据、回滚 | `docs/04-load-baseline-and-rollback.md` |
| 换机型要重算哪些常量、按什么顺序验证 | `docs/05-port-to-another-device.md` |
| 编译选项与可复现构建 | `src/gl/BUILD.md`、`src/ksu/BUILD.md` |

## 没收录什么

有三样故意不在仓库里，原因不同，写清楚省得有人以为漏了：

| 不在仓库的 | 原因 | 你需要怎么办 |
|---|---|---|
| 1.4 GB vendor 内核树 | 厂商代码，体积也不是 git 该装的东西 | 自备同版本 4.19.191 源码树，`.config` 用 `config/` 里那份，见 `src/ksu/BUILD.md` |
| ksud 用户态源码（Rust） | 上游 KernelSU 的组件，这次没有改动 | 载荷里的 `libksud.so` 是编好的成品，随 `ksu` 落盘即用，不需要自己编 |
| 管理器 App | 上游 KernelSU 官方应用 | 装官方 App，它能认出 32715 / UAPI 6 的内核侧 |

## 从头复现的完整路径

```sh
# 1) 内核模块：内核树 + config/pju110_4.19.191.config，按 src/ksu/BUILD.md 编出 ksu_raw.ko
# 2) 喷射程序：
aarch64-linux-gnu-gcc -static -O2 -pthread src/gl/gl_pju110.c -o gl_v112
# 3) allowlist（参数依次是 uid、包名、SELinux 域、输出文件）：
python3 src/tools/gen_allowlist.py 10266 me.weishu.kernelsu u:r:ksu:s0 allowlist.bin
# 4) 组装：目录里放 lt/gl_v112 和 dl/{ksu_raw.ko,libksud.so,allowlist.bin}
sh tools/pack.sh <那个目录> main/ksu.new
# 5) 自检
sh tools/verify.sh
```

第 2 步编出来的 `gl_v112` 与仓库载荷**逻辑等价但字节不同**：换了编译器版本，指令排布会变，
喷射时序跟着变，所以不建议直接替换载荷。`src/gl/BUILD.md` 里有实测差异数据。

## 许可

- `src/ksu/kernel`、`src/ksu/uapi` 是 KernelSU 的 4.19 适配副本，**GPL-3.0**，全文见 `src/ksu/LICENSE`，改动范围见 `src/ksu/NOTICE`。
- 载荷里的 `ksu_raw.ko`、`libksud.so` 由上述 GPL-3.0 源码编出，同样受 GPL-3.0 约束。
- `src/gl/`、`main/`、`tools/`、`docs/` 未附许可证，默认保留权利；要用请自行判断风险。

## 免责

写这个是为了在自己有处置权的设备上拿 root。栈喷射改的是内核内存，任何一步没对上都会导致重启甚至起不来。
换内核、换机型、换 ROM 都不要直接套用。按 `docs/04` 的方法先备份、先确认判据，再动手。