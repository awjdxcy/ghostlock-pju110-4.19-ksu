#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "hook/lsm_hook.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "feature/sulog.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "feature/adb_root.h"
#include "feature/selinux_hide.h"
#include "feature/module_blacklist.h"
#include "feature/shell_su_adb_only.h"
#include "infra/symbol_resolver.h"
#ifdef KSU_54
#include "ksu54_syms.h"
#endif

#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
    (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

#ifdef MODULE
bool ksu_bundled = false;
module_param_named(bundled, ksu_bundled, bool, 0);
#endif

int __init kernelsu_init(void)
{
    pr_info("welcome to KernelSU version " __stringify(KERNEL_SU_VERSION) ", package name " KSU_PACKAGE_NAME "\n");
#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
    // If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      KernelSU will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif
    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOSYS;
    }

    ksu_init_symbol_resolver();
    ksu_syscall_hook_init();

    // Block modules early, before vendor modules are loaded in second stage.
    ksu_module_blacklist_init();

    ksu_feature_init();
    ksu_sulog_init();
    ksu_adb_root_init();
    ksu_lsm_hook_init();
    ksu_selinux_hide_init();
    ksu_shell_su_adb_only_init();

    ksu_supercalls_init();
    ksu_app_profile_init();

    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        /* 4.19: 我们的加载进程是通过 cred 指针改写拿到 root 的
         * （task->cred = init_cred，但 real_cred 仍是 shell），
         * 这里再走 commit_creds 会命中它的
         *   BUG_ON(task->cred != task->real_cred)
         * → MTK ipanic 直接重启。而该调用的唯一目的是"把加载进程本身
         * 变成 root + 切到 ksu 域"，对我们已经无意义，故在 4.19 跳过。 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        escape_to_root_for_init();
#endif

        ksu_allowlist_init();
        ksu_load_allow_list();

        ksu_syscall_hook_manager_init();

#ifdef KSU_54
        /* Disable the hidden ColorOS anti-root SIGKILL before anything tries
         * to escalate an app process to uid 0. */
        ksu54_patch_vendor_root_check();
#endif

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        track_throne(false);

        ksu_feature_apply_forced();

#ifndef KSU_54
        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }
#else
        /*
         * 4.19：策略已由模块内的 rules54 原生注入（含 ksu / ksu_file 两个
         * type 与 ksu 域的 permissive 标记），因此这里可以把全局 SELinux
         * 从 permissive 切回严格执行，让越狱只在"漏洞窗口期"处于宽松状态。
         *
         * 顺序很关键：必须先 setenforce(true)，再 avc_ss_reset()。否则
         * permissive 期间缓存的 allow 结论会在 enforcing 之后继续放行。
         * 排障时可用 insmod 参数 enforce_after=0 关闭这一步。
         */
        if (ksu54_enforce_after && !getenforce()) {
            pr_info("ksu54: policy injected, restoring SELinux enforcing\n");
            setenforce(true);
            ksu54_avc_flush();
            pr_info("ksu54: SELinux enforce now = %d\n", getenforce());
        } else {
            pr_info("ksu54: keep SELinux enforcing state unchanged (%d)\n", getenforce());
        }
#endif

    } else {
        ksu_syscall_hook_manager_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();

        ksu_file_wrapper_init();
    }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
#ifndef KSU_54
    /* On this vendor 5.4 kernel, free_module() crashes when the module's
     * sysfs kobject was already deleted, so keep it on 5.4. */
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
#endif
    return 0;
}

void __exit kernelsu_exit(void)
{
    // Phase 1: Stop all hooks first to prevent new callbacks
    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    if (!ksu_late_loaded)
        ksu_ksud_exit();

    // Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
    synchronize_rcu();

    // Phase 2: Now safe to release data structures
    ksu_observer_exit();

    ksu_throne_tracker_exit();

    ksu_allowlist_exit();

    ksu_shell_su_adb_only_exit();
    ksu_selinux_hide_exit();
    ksu_lsm_hook_exit();
    ksu_adb_root_exit();
    ksu_sulog_exit();
    ksu_feature_exit();
    ksu_module_blacklist_exit();

    put_cred(ksu_cred);
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
