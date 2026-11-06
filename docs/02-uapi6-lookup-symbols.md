# 在 4.19 上补 UAPI6 的 `LOOKUP_SYMBOLS`

## 起点：为什么非要动它

新版管理器按 UAPI 版本判断能不能用，内核还是 32680 / UAPI 5 时首页会提示“需要更新内核”。
要消掉这个提示，模块得升到 32715 / UAPI 6。

UAPI 6 相对 5 的新增项里，真正要写代码的只有一个：

```c
#define KSU_IOCTL_LOOKUP_SYMBOLS _IOW('K', 22, struct ksu_lookup_symbols_cmd)
#define KSU_LOOKUP_SYMBOLS_MAX 1024

struct ksu_lookup_symbols_cmd {
    __aligned_u64 names;    /* const char *names[] 用户态指针数组 */
    __aligned_u64 addrs;    /* u64 addrs[] 输出 */
    __u32 count;
    __u32 flags;
};
```

另外还有一个 `KSU_GET_INFO_FLAG_PREINIT = 1 << 5`，见文末。

## 上游的实现，和我们这里为什么不能用

上游遍历符号用的是 `kallsyms_on_each_symbol`。这颗 vendor 内核（4.19.191）既没导出它，
也没有稳定签名可对 —— 直接调用连编译都过不去。

好在这个模块早就有一条自己的符号解析通路，是为 CFI 环境准备的跳板：

```
find_kernel_symbol_exact()   ← 在模块维护的符号表里按名字精确找
        ↓
ksu54_lookup_sym()           ← 需要内核地址时改走 kln
        ↓
ksu54_blr()                  ← 绕 CFI 的间接调用
```

于是 `do_lookup_symbols()` 就架在这条路上逐名解析，不去碰 `kallsyms_on_each_symbol`。

## 语义必须和上游对齐

接口是给用户态用的，行为不一致就是 bug。这三条一一对齐：

| 行为 | 处理 |
|---|---|
| 不返回模块自己的符号 | 只走内核符号表 |
| 同名多个时首个匹配优先 | 与上游一致 |
| 解析不到 | 写 0，不报错 |
| `count > 1024` | 直接 `-EINVAL`，不截断 |
| 权限 | `only_root`，与其余管理类超调用一致 |

## 两个坑

### 1. `strndup_user` 会给你多带一个未定义符号

第一版图省事，用 `strndup_user()` 拷用户态字符串。编译没问题，但 `llvm-nm -u` 立刻多出一行：

```
U strndup_user
```

这个模块的加载方式是**先提权再 `insmod`**，未定义符号表里每多一个符号，就多一个“内核没导出 → 加载失败”的风险。
上一版能跑不代表这一版能跑，所以这条不能忍。

改成手写：

```c
name = kmalloc(KSYM_NAME_LEN, GFP_KERNEL);
len = strncpy_from_user(name, (const char __user *)uname, KSYM_NAME_LEN);
if (len < 0) { ... }
```

改完之后：

```sh
diff <(llvm-nm -u 32680.ko) <(llvm-nm -u 32715.ko)
# 空输出
```

`__versions` 段的 md5 也一致。这是这次改动能被接受的前提 —— **未定义符号一个都不能多**。

### 2. `KSYM_NAME_LEN` 未声明

```
error: 'KSYM_NAME_LEN' undeclared
```

补一行 `#include <linux/kallsyms.h>` 即可。上游那套代码里它是间接带进来的，4.19 上不带。

## 二进制层面怎么确认真的生效了

源码改完不算完，得看产物：

```sh
# 版本号 32715 = 0x7FCB
llvm-objdump -d kernelsu.ko | grep -m1 'mov.*w12, #0x7fcb'

# UAPI 版本 6
llvm-objdump -d kernelsu.ko | grep -m1 'movk.*x9, #0x6, lsl #32'

# 字符串进了 .rodata（说明命令表真的注册了）
llvm-objdump -s -j .rodata kernelsu.ko | grep -o LOOKUP_SYMBOLS

# CFI 跳板生成了
llvm-nm kernelsu.ko | grep do_lookup_symbols.cfi_jt

# vermagic 没变（变了就装不上）
modinfo kernelsu.ko | grep vermagic
# vermagic: 4.19.191+ SMP preempt mod_unload modversions aarch64
```

ioctl 编号也要确认没撞车：`22` 号此前在这个模块里没被用过。

## `PREINIT` 这一档故意不做

`KSU_GET_INFO_FLAG_PREINIT` 的语义是“模块在 PID 1 的早期阶段就已经在跑了，那它可以参与 `selinux_setup`”。
本机的加载方式是 **late-load**：系统起来之后由 exploit 提权再 `insmod`，根本看不到 PID 1 的 `selinux_setup`。

所以这个 flag 不置位。管理器收到之后会正确判定“不支持 preinit”，`requiresNewKernel` 不会触发，
现有功能一个不受影响。硬要置位反而是撒谎 —— 之后 preinit 相关的东西一定会报错。

## 拿不到也没关系

上游 ksud 对这个接口做了降级：调用失败就退回读 `/proc/kallsyms`。所以 `LOOKUP_SYMBOLS` 属于**增强项**，
不是启动必需。这一点对“改坏了会不会开不了机”这个担心很有用 —— 最坏情况是功能缺失，不是起不来。