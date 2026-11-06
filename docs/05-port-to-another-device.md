# 换一台手机：要重算什么，按什么顺序

先把结论摆在前面：**这份代码不是跨机型通用工具。** `src/gl/gl_pju110.c` 里有 49 处内核地址是写死的，加上槽位偏移、结构体偏移、模块的 `kln=` 静态地址，全部绑死 PJU110 这一份 `vmlinux`。

别人要在别的机型上跑通，能复用的是**方法与结构**，不能复用的是**数值**。这一篇讲的就是：哪些数值要重算、从哪来、算错了会怎样。

## 第 0 步：先判断这台机器能不能做

| 条件 | 为什么要 | 不满足会怎样 |
|---|---|---|
| 内核 4.19.x | 整条链是按 4.19 的 `rt_mutex` 与 `task_struct` 布局写的 | 换大版本要重写，不是改数字的事 |
| arm64 | 栈帧、寄存器约定、`-ffixed-x18` 全是 arm64 的 | 无解 |
| 有 `vmlinux` 且带符号表 | 所有静态地址都从符号表读 | 只有 `Image` 的话基本没法做 |
| `CONFIG_KALLSYMS_ALL=y` | 模块要按名字解析符号 | 解析拿不到目标，装载后 hook 全是空指针 |
| `CONFIG_MODULES=y` + 可装载 | 模块是唯一的落地点 | 无解 |
| SELinux `enforcing` | 链路的第 1 步就是把它切宽容 | 已经是宽容的话第 1 步自动跳过，不碍事 |

内核配置可以从设备上直接导出，做法就是本仓库 `config/pju110_4.19.191.config` 的来源：

```sh
zcat /proc/config.gz > my.config
```

## 第 1 步：从符号表取地址

```sh
nm -n vmlinux | grep -E ' (_text|selinux_state|empty_zero_page|init_task|init_cred|commit_creds)$'
nm -n vmlinux | grep -E ' (sig_enforce|kptr_restrict|panic_on_oops)$'
```

`_text` 同时也是 KASLR 的基准（`LINK_TEXT`），`TEXT_OFFSET` 是 `_text` 相对镜像基址的偏移。

`kallsyms_lookup_name` 的地址要单独取：

```sh
nm -n vmlinux | grep ' kallsyms_lookup_name$'
```

这个值会被填进模块参数的 `kln=0x...`，运行时加上实际 slide 再传给 `init_module`。

## 第 2 步：要改的常量清单

全部在 `src/gl/gl_pju110.c` 顶部，表格里「本机值」来自 PJU110 的 `vmlinux`，**不能直接抄到别的机器**。

| 常量 | 本机值 | 从哪来 |
|---|---|---|
| `LINK_TEXT` | `0xffffff8008080000` | `nm vmlinux \| grep ' _text$'` |
| `TEXT_OFFSET` | `0x00080000` | `_text - image_base` |
| `SELINUX_STATE_S` | `0xffffff800b1b8bd8` | `nm` 查 `selinux_state` |
| `EMPTY_ZERO_S` | `0xffffff800ae4c000` | `nm` 查 `empty_zero_page` |
| `INIT_TASK_S` | `0xffffff800aaf25c0` | `nm` 查 `init_task` |
| `SIG_ENFORCE_S` | `0xffffff800ab0a9f0` | `nm` 查 `sig_enforce`；也可反汇编 `is_module_sig_enforced` 印证 |
| `KPTR_RESTRICT_S` | `0xffffff800aa6e428` | `nm` 查 `kptr_restrict` |
| `PANIC_ON_OOPS_S` | `0xffffff800aaf67e8` | `nm` 查 `panic_on_oops` |
| `BSS_SCRATCH_S` | `0xffffff800ae4d000` | `.bss` 里的全零页（本机是 `bm_pmd`） |
| `LINK_INIT_CRED` | `0xffffff800aafcf78` | `nm` 查 `init_cred` |
| `LINK_COMMIT_CREDS` | `0xffffff80082968fc` | `nm` 查 `commit_creds` |
| `TASK_REAL_CRED` | `0x760` | `task_struct` 里 `real_cred` 的偏移，用 `pahole` 或从 `vmlinux` 的 DWARF 读 |
| `TASK_CRED` | `0x768` | 同上，`cred` 的偏移 |
| `kln=` 静态地址 | `0xffffff800833745c` | `nm` 查 `kallsyms_lookup_name`，写在 `gl_pju110.c` 的 `snprintf` 里 |

结构体偏移（`0x760`/`0x768`）**随内核配置变**：开了 `CONFIG_DEBUG_LOCK_ALLOC`、`CONFIG_SECURITY`、`CONFIG_KASAN` 都会挪位置，必须逐机型查。

## 第 3 步：槽位偏移不能抄

源码里 `SCR_LOCK1` … `SCR_LOCK14` 是 `0x040`~`0x780` 的一批值，它们不是随便取的，受两个约束：

1. **落点要落在栈帧里合适的深度**：`iovstack_r` 落栈位置与 `rt_mutex` waiter 相差 `-0x40`（本机实测），所以候选值按 `0x40` 步进；
2. **不能跨页**：本机写入点相对栈页首约 `0x84C`，所以 `0x84C + slot < 0x1000`，即 `slot < 0x7B4`。这就是为什么槽位最大只到 `0x780`。

换机型时这两个数都要重测：先在目标机上把 `iovstack_r` 与 waiter 的实际间距量出来，再按 `0x40` 步进铺候选，最后用 `slot < (0x1000 - 写入点偏移)` 剪掉越界的。

**怎么试**：每个候选单独跑一次，读 `/sys/fs/selinux/enforce` 判断有没有命中。仓库里的 `sh ksu relax` 就是只做这一步 —— 只切 SELinux，不做后面的提权和装载。适配新机型时，先让 `relax` 稳定命中，再往下做。

## 第 4 步：模块侧要改的

| 项 | 说明 |
|---|---|
| `vermagic` | 自动跟内核走，但必须和**目标机运行中的内核**完全一致，否则 `init_module` 直接拒绝 |
| `-ffixed-x18` | 必须保留。见 `src/ksu/BUILD.md`，out-of-tree 构建不继承内核的这条选项，漏了会在第一次用到 `x18` 时崩 |
| 空 `Module.symvers` | 用空文件，让所有符号走模块内的解析器；否则会用错版本符号 |
| `kln=` 参数 | 静态地址按第 1 步重新取，运行时加 slide |
| `enforce_after` | 默认 1，装载后把 `enforcing` 写回 1；调试阶段可以传 0 观察 |

## 第 5 步：按这个顺序验证

| 顺序 | 命令 | 通过的样子 | 失败的样子 |
|---|---|---|---|
| 1 | `sh ksu check` | 四行状态正常打印 | 连日志都不出，可能是 `/data/local/tmp` 不可写 |
| 2 | `sh ksu relax` | `已切宽容`，`getenforce` 变 `Permissive` | `切宽容失败`，看 `k1.log` 尾部 |
| 3 | `sh ksu` | 五步全过，模块 `Live` | 卡在哪一步就看那个 `n/5` |
| 4 | 重启后再跑一次 | 幂等，或干净重来 | 掉进 `槽位用尽`，说明台账没跟着 `boot_id` 清 |

## 别做的事

- **不要拿一个机型算出来的地址去试另一个机型。** 地址是错的，写入点也是错的，最轻是没反应，最常见是内核 Oops 重启，最坏是把无关内存写坏、进不了系统。
- **不要跳过 `relax` 直接跑全流程。** 第 1 步不中，后面几步全在错误的栈状态上做，只能得到误导性的失败。
- **不要在 `vermagic` 不一致时硬装。** 内核会拒绝，你要是绕过了这一层，后果是符号错位调用，崩在别处。