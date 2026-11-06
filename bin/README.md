# 预编译件清单

仓库里**只有一份二进制**：全部在 `main/ksu` 的尾部载荷里，不另外复制一套。
需要单独取出来时：

```sh
sh tools/unpack.sh main/ksu ./payload
```

## main/ksu

| 项 | 值 |
|---|---|
| 大小 | 5,709,338 字节 |
| md5 | `8b089395cc0368ed84f2bf9cbcb7388b` |
| 头部（脚本体） | 17,572 字节，md5 `9697aa20686d1b45836da3fe74da21b3` |
| 载荷起点 | `PAYLOAD_OFFSET=17573` |
| 载荷压缩 | gzip + tar，解出 4 个文件 |

## 载荷四件

| 文件 | 大小 | md5 | 落到设备的位置 |
|---|---|---|---|
| `lt/gl_v112` | 870,760 | `2c4717dc596daca084f7317250fc8765` | 工作目录，`selinux` / `sig` / `run` 三个子命令 |
| `dl/ksu_raw.ko` | 4,697,872 | `44608d0d3fa8777304a6be1af069ecb9` | `/sdcard/Download/ksu_raw.ko` |
| `dl/libksud.so` | 4,990,848 | `b7b87ee9dc0e57a393a28d88055e06fa` | `/sdcard/Download/libksud.so` → 装成 `/data/adb/ksud` |
| `dl/allowlist.bin` | 792 | `c4221d6f192bebe8639223513cf7ac00` | `/sdcard/Download/allowlist.bin` |

`allowlist.bin` 只有两项，没有三方包名：`me.weishu.kernelsu` / `u:r:ksu:s0`。
需要重新生成用 `src/tools/gen_allowlist.py`。

## 模块符号是怎么解决的

`ksu_raw.ko` 里有 5 个内核没导出的符号，靠的是**模块参数**而不是二进制补丁：

```c
unsigned long ksu54_kln __read_mostly;
module_param_named(kln, ksu54_kln, ulong, 0);
```

装载时由 `gl_v112 run` 直接 `init_module`，把地址塞进参数里：

```c
snprintf(param, sizeof(param), "kln=0x%lx level=3",
         (unsigned long)(0xffffff800833745cUL + g_slide));
syscall(__NR_init_module, ko, size, param);
```

- `0xffffff800833745c` 是本机 `kallsyms_lookup_name` 的静态地址（未加 KASLR 偏移）
- `g_slide` 是运行期算出来的 KASLR slide
- `level=3` 表示 late-load

其余符号全部由模块自己在这个地址上按名字解析。**所以换内核必须换掉那个静态地址**，
这也是为什么这份产物只能跑在 `4.19.191+` 上。

## 关于 strip

`.ko` 是 4,697,872 字节，其中约 4.4 MB 是 `.debug_*`，strip 完大约 292 KB —— 技术上能 strip 也能加载。

这里不 strip 的原因很朴素：**它就是本机验证通过的那一份**。载入流程里 `init_module` 的
size 参数取的是文件实际大小，内容一改就等于换了个没验证过的模块，得重新在真机上跑一遍
（并且会踩一次重启）。留着调试信息，panic 时能直接 `addr2line` 定位到行。

要换成自己编的模块，走 `tools/repack.sh`，然后按 `docs/04` 的判据重新验证一次。

## 校验

```sh
sh tools/verify.sh
```

做三件事：头部长度与 `PAYLOAD_OFFSET` 自洽 → 头部 shell 语法 → 四件载荷 md5 全对，返回 0 才算过。