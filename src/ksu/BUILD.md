# 编出 `kernelsu.ko`（4.19 适配）

## 前置

| 需要 | 说明 |
|---|---|
| 内核树 | 与本机同版本的 vendor 4.19.191 源码，**且 `.config` 必须和设备一致** |
| `.config` | 直接用 `config/pju110_4.19.191.config`（从设备 `/proc/config.gz` 导出，6211 行） |
| 工具链 | `clang` + `ld.lld`（本机用的是 LLVM 18，`/usr/lib/llvm-18/bin`） |
| `vmlinux` | `tools/check_symbol` 要用它做未定义符号核对 |

## 构建

```sh
cd src/ksu/kernel
make -C /path/to/kernel-4.19.191 \
     M=$PWD src=$PWD \
     ARCH=arm64 \
     CC=clang LD=ld.lld \
     modules -j$(nproc)
```

产物 `kernelsu.ko`。`Makefile` 末尾会跑一次 `check_symbol kernelsu.ko <KDIR>/vmlinux`，
核对模块引用但内核没导出的符号 —— 这一步不能跳过，它是“能不能装上”的判据。

## 三条必须记住的编译选项

### ① `-ffixed-x18`（`Kbuild:174`）

```make
ccflags-y += -ffixed-x18
```

`arch/arm64/Makefile` 给内核自己加了这条，但 out-of-tree 构建不继承。缺了它，`x18` 就会
被编译器当普通寄存器跨调用持有，然后被内核当 TLS 指针改写 —— 一次 `insmod` 直接 panic。
完整因果见 `docs/01-x18-register-panic.md`。

顺带：**不要**在内联汇编的 clobber 列表里再写 `"x18"`，`ld.lld` 会警告
`inline asm clobber list contains reserved registers: X18`。两者不能同时用。

### ② `Module.symvers` 用空表

这颗 vendor 内核的 `__kcrctab_*` 全是 0，设备自带 28 个 `.ko` 的 `__versions` 并集也只有一千多个符号，
重建完整 CRC 表既做不到也不需要。`kernel/module.c: check_version()` 的逻辑是：

```c
/* Broken toolchain. Warn once, then let it go.. */
pr_warn_once("%s: no symbol version for %s\n", ...);
return 1;                       ← 缺条目 = 放行
bad_version:
pr_warn("disagrees about version of symbol %s\n", ...);
return 0;                       ← 有条目但值不相等才致命
```

所以给一份**空的** `Module.symvers` 是最稳的：所有导入都走“无版本 + 警告”分支，不会 mismatch。

### ③ 未定义符号表必须与上一版逐行一致

```sh
diff <(llvm-nm -u old.ko) <(llvm-nm -u new.ko)
```

这次升级 UAPI6 时，为了保持这个 diff 为空，把 `strndup_user` 换成了
`kmalloc + strncpy_from_user`（否则会多出一条 `U strndup_user`）。理由很简单：
多一个未定义符号 = 多一个加载失败的可能，而这类失败表现为“装不上”甚至“装上去崩”。

## 符号怎么解决

模块不依赖内核导出，而是收一个地址：

```c
unsigned long ksu54_kln __read_mostly;
module_param_named(kln, ksu54_kln, ulong, 0);
```

装载方（`gl_pju110 run`）把 `kallsyms_lookup_name` 的运行时地址塞进 `kln=`，其余符号由模块自己解析。
`level=3` 表示 late-load，与 `PREINIT` 那一档的判定相关（见 `docs/02`）。

## 产物

| 项 | 值 |
|---|---|
| 大小 | 4,697,872 字节（未 strip） |
| md5 | `44608d0d3fa8777304a6be1af069ecb9` |
| vermagic | `4.19.191+ SMP preempt mod_unload modversions aarch64` |
| 版本 | 32715 / UAPI 6 |

编出新的 `.ko` 之后不要直接覆盖设备上的文件 —— 走 `tools/repack.sh` 换进 `main/ksu` 的载荷，
再按 `docs/04` 的判据重新验证。

## 许可证

`kernel/` 下的代码来自 KernelSU（GPL-3.0，见同目录 `LICENSE` 与 `NOTICE`），
4.19 适配与 UAPI6 补丁沿用同一许可。分发前请保持许可证文件完整。