# 单文件脚本的结构：为什么只换外部的 `ksu_raw.ko` 不生效

## 文件长什么样

`main/ksu` 是一个 **shell 脚本 + 压缩载荷** 拼起来的文件，5,709,338 字节：

```
偏移 0            ……… 17,572        17,573 ………………………………… 5,709,338
[      脚本体（shell，469 行）      ][   gzip 流 → tar，解出 4 个文件  ]
                                    ↑
                            PAYLOAD_OFFSET=17573
```

脚本体里写死了一行：

```sh
PAYLOAD_OFFSET=17573
```

运行时它这样取自己：

```sh
tail -c "+$PAYLOAD_OFFSET" "$SELF" | gzip -d | tar x -C "$_d"
```

解出的四个文件是 `lt/gl_v112`、`dl/ksu_raw.ko`、`dl/libksud.so`、`dl/allowlist.bin`，
随后覆盖到设备上的固定位置。

## 于是“只替换模块”这条路是死的

最初的想法很自然：要换新版模块，就把 `/sdcard/Download/ksu_raw.ko` 换成新的。
但脚本每次运行都会**先用自己尾部的载荷把那个文件写回来**，所以：

```
你换掉外部 ko  →  跑一次脚本  →  ko 被载荷覆盖回旧版  →  还是旧版在加载
```

必须换的是**载荷本身**，不是它释放出来的副本。

## 正确的换法

`tools/repack.sh` 干的就是这件事，三个动作：

1. 按 `PAYLOAD_OFFSET` 把文件切成 `head.bin` 和 `payload.gz` 两段；
2. 解开 `payload.gz`，只覆盖你要换的那一个文件，其余三个原封不动；
3. 重新 `tar | gzip`，拼回 `head.bin` 前面，**头部一个字节都不动**。

```sh
sh tools/repack.sh main/ksu new_ksu_raw.ko dl/ksu_raw.ko ksu_new
```

脚本会自己打印头部 md5（新/旧）和四件载荷的 md5，用来核对。

## 三条硬约束

**① 头部长度必须严格等于 `PAYLOAD_OFFSET - 1`。**

多一个字节，偏移就错位，`tail -c` 从 gzip 流中间开始读，解包直接失败。这是为什么改脚本体之后
必检：

```sh
awk 'index($0,"PAYLOAD_OFFSET=")==1' main/ksu
wc -c < main/ksu      # 应等于 17572 + 载荷长度
```

**② 载荷里的路径必须保持 `lt/` 和 `dl/` 两个目录。**

脚本按 `lt/gl_v112`、`dl/ksu_raw.ko` 这样取文件，改目录名等于让脚本找不到载荷。
`repack.sh` 里对这条做了校验，非 `lt/`、`dl/` 开头的路径直接拒绝。

**③ 重打包会改变整个文件的 md5，但功能不变。**

gzip 的压缩级别、tar 的条目顺序都会影响压缩后的字节。实测拿原 ko 回填重打包，得到 5,698,795 字节
（比原始少 10,543 字节），头部 md5 与原文件完全一致，四件载荷 md5 也全部一致 —— 功能等价，文件哈希不同。
所以**不要拿整文件 md5 判断“是不是同一份”**，看头部 md5 + 四件载荷 md5。

## 校验方式

整文件过 `sh -n` 一定会报错，因为尾部是二进制。只校验头部：

```sh
head -c 17572 main/ksu | sh -n && echo header_ok
```

真实解包校验（这一步才算数）：

```sh
sh tools/unpack.sh main/ksu /tmp/payload
sh tools/verify.sh
```

`verify.sh` 会做：头部长度自洽 → 头部语法 → 四件载荷 md5 → 辅助件是否存在。

## 一次成功的换件记录

换模块（32680 → 32715 / UAPI6）时的实际输出：

```
输入   : main/ksu (5709338 字节)
替换   : dl/ksu_raw.ko  ←  ksu_raw.ko
输出   : ksu_new (5709394 字节)
头部   : 17572 字节（应等于 17572）
头 md5 : 9697aa20686d1b45836da3fe74da21b3
     原 : 9697aa20686d1b45836da3fe74da21b3
自检：解包输出的载荷
  lt/gl_v112             870760  2c4717dc596daca084f7317250fc8765
  dl/ksu_raw.ko         4697872  44608d0d3fa8777304a6be1af069ecb9
  dl/libksud.so         4990848  b7b87ee9dc0e57a393a28d88055e06fa
  dl/allowlist.bin          792  c4221d6f192bebe8639223513cf7ac00
```

除 `ksu_raw.ko` 换了 md5，其余三件一个字节没变 —— 这就是“只换了模块”的可验证证据。