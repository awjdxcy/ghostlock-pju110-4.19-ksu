// PJU110 / 4.19.191 compatibility shims
//
// 1) find_task_by_vpid() / get_task_cred() 在 4.19 都没有 EXPORT_SYMBOL，
//    模块无法直接链接，改为通过 kln 解析运行时地址后调用。
// 2) selinux 策略注入（sepolicy.o / rules54.o / ksu54_secops.o）在 4.19 上
//    编译裁剪掉了，这里给出空实现，保证链接通过。
// 3) LSM hook 增强（hook/lsm_hook.o）依赖 5.1+ 的 lsm_blob_sizes，同样空实现。

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/errno.h>

#include "infra/symbol_resolver.h"

struct task_struct *find_task_by_vpid(pid_t nr)
{
    static struct task_struct *(*fn)(pid_t);

    /* ★ 间接调用内核函数必须走 .cfi_jt（CFI 跳表入口），
     *   否则 CONFIG_CFI_CLANG 下 __cfi_check 会因类型哈希不匹配直接 BUG。
     *   （get_task_cred 那个垫片就是这么炸的，见下方注释） */
    if (!fn)
        fn = (void *)ksu_resolve_symbol_for_functable_hook("find_task_by_vpid");
    if (!fn) {
        pr_err("ksu419: find_task_by_vpid not resolved\n");
        return NULL;
    }
    return fn(nr);
}

/* ★★★ 关键修正（v2）：get_task_cred 必须内联实现，不能间接调用 ★★★
 *
 * 旧实现是：
 *     static const struct cred *(*fn)(struct task_struct *);
 *     fn = (void *)find_kernel_symbol_exact("get_task_cred");
 *     return fn(task);              ← 间接调用
 *
 * 实测崩在（管理器切换应用 profile 时）：
 *     __cfi_check_fail+0x14/0x18
 *     __cfi_check+0x67a40/0x6c9d8
 *     get_task_cred+0x50/0x7c [kernelsu]     ← 就是我们这个垫片
 *     ksu_mark_running_process_locked → do_set_app_profile
 *     → Kernel BUG → ipanic → 重启
 *
 * 该内核 CONFIG_CFI_CLANG=y + CFI_CLANG_SHADOW=y，模块通过函数指针调用
 * 内核函数时会走 __cfi_check 校验类型哈希；这里签名/影子表对不上就直接 panic。
 *
 * 下面的实现等价于 4.19 原生 kernel/cred.c:191，但整个函数体只有
 *   rcu_read_lock + rcu_dereference(task->real_cred) + atomic_inc_not_zero
 * —— 纯内存/原子操作，没有任何间接调用 ⇒ 永远不会触发 CFI 检查。
 */
const struct cred *get_task_cred(struct task_struct *task)
{
    const struct cred *cred;

    if (!task)
        return NULL;

    rcu_read_lock();
    do {
        cred = __task_cred(task);
        if (!cred)
            break;
    } while (!atomic_inc_not_zero(&((struct cred *)cred)->usage));
    rcu_read_unlock();

    return cred;
}

/*
 * 4.19 原生策略注入已启用（selinux/sepolicy.o + selinux/rules54.o 参与编译），
 * apply_kernelsu_rules() 由 rules54.c 提供真正的 policydb 改写实现，
 * 这里不再需要空桩；handle_sepolicy() 同样由 rules54.c 提供。
 */

void ksu_lsm_hook_init(void)
{
}

void ksu_lsm_hook_exit(void)
{
}
