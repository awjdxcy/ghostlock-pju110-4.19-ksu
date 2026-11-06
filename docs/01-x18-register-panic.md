# 一次 `insmod` 就把机器炸掉：x18 被当成普通寄存器用了

## 现象

模块第一次加载，屏幕黑、设备硬重启，没有任何可操作的窗口。`panic_on_oops=1`，所以没有 soft reboot。

重启后从 `/proc/last_kmsg` 里捞到原始栈：

```
Unable to handle kernel paging request at virtual address 000000000000b758
pgd = ffffff800e1a0000
pud = ffffff800e1a0000
pmd = 0000000000000000
Internal error: Oops: 96000006 [#1] PREEMPT SMP
pc : ksu54_resolve_all+0xbc/0x198 [kernelsu]
```

两个关键信息：出错地址 `0xb758` 小得离谱，不可能是内核地址；`pc` 落在我们自己的模块里。

## 崩溃的那条指令

`llvm-objdump -d` 定位 `+0xbc`：

```asm
ldr x3, [x18]
```

而 `x18` 当时的值是 `0xb538` —— 也不是地址，是个小整数。

## x18 为什么特殊

`x18` 是 AArch64 的**平台寄存器**。内核在 `arch/arm64/Makefile` 里统一给所有编译单元加 `-ffixed-x18`，
让编译器永远不把它当临时寄存器用（Android 用它指向 TLS）。

但 **out-of-tree 模块不继承这条 cflags**。`M=` 构建时只会带上我们自己写的那几行。查证方式很直接 ——
构建目录里 `.ksu54_syms.o.cmd` 的 `cflags` 中 `-ffixed-x18` 出现次数为 **0**：

```sh
grep -o '\-ffixed-x18' .ksu54_syms.o.cmd | wc -l
# 0
```

所以在这个模块里，`x18` 就是个普通寄存器，clang 完全可以把它当作“跨函数调用要保活的指针”来用。

## 为什么升级版本才炸

把两个版本的 `ksu54_resolve_all` 反汇编摆在一起：指令几乎逐条相同，整体偏移只差 4 字节。
唯一的实质差别是 `adrp x18` 的位置：

| 版本 | `adrp x18` 的位置 | 后果 |
|---|---|---|
| 32680（旧） | 在 `blr` **之后** | 调用回来才取地址，x18 刚被内核破坏也没关系，反正马上重新赋值 |
| 32715（新） | 在 `blr` **之前** | 想在调用前先算好地址留着用，结果调用返回后 x18 已不是自己的数据，一解引用就炸 |

`blr` 走的是绕 CFI 的跳板，实际落到内核函数里。内核自己遵守 `-ffixed-x18` 吗？内核代码是遵守的，
但**它有权把 x18 当 TLS 指针用** —— 调用返回时 x18 里是内核的 TLS 基址，不是我们塞进去的值。

于是因果关系很清楚：不是新写的逻辑有错，而是 UAPI6 的改动让编译单元变大，LTO 重排了寄存器分配，
把一个一直存在的隐患"挪"到了暴露的位置。旧版只是恰好躲过去了。

## 修法（两件事，缺一不可）

**第一，在 `Kbuild` 里补上固定寄存器：**

```make
ccflags-y += -ffixed-x18
```

**第二，把 `ksu54_blr()` 内联汇编 clobber 列表里那个 `x18` 删掉。**

第二条容易搞反。既然要保护 `x18`，为什么不干脆在 clobber 里写 `"x18"`？因为写进去的意思是
“我这条 asm 会修改 x18”，而 `x18` 已经被 `-ffixed-x18` 从分配池里拿走，`ld.lld` 会直接警告：

```
inline asm clobber list contains reserved registers: X18
```

正确姿势是：**clobber 列表里不出现 x18，靠 `-ffixed-x18` 让它根本不参与分配。** 两者同时存在只会换来链接器警告。

## 怎么确认修好了

```sh
# 1) .text 里不该再出现 x18
llvm-objdump -d -j .text kernelsu.ko | grep -c x18
# 0

# 2) 崩溃现场那个函数改用普通寄存器了（x16 / x21 之类）
llvm-objdump -d kernelsu.ko | sed -n '/<ksu54_resolve_all>:/,/^$/p' | head -30
```

还有一个必须做的检查 —— 未定义符号表不能变，否则等于引入了新的加载失败风险：

```sh
diff <(llvm-nm -u old.ko) <(llvm-nm -u new.ko)
# 空输出
```

## 给别人提个醒

1. out-of-tree 编 arm64 模块，第一条 cflags 就应该是 `-ffixed-x18`。内核自己加了，不代表你的模块也有。
2. 内联汇编里别把平台寄存器当普通暂存器用，更别跨调用持有指针。
3. 每次改完代码，跑一次 `grep -c x18`。这个检查比读一遍 diff 有效 —— 区别可能就藏在寄存器分配里。