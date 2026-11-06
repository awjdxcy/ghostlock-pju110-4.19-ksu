# 耗时基线、判据、回滚

## 一次成功长什么样

四条都要对：

```sh
cat /proc/modules | grep kernelsu
# kernelsu 184320 0 - Live 0xffffffa1xxxxxxxx (OE)

cat /sys/fs/selinux/enforce
# 1

ls -d /sys/module/kernelsu
# /sys/module/kernelsu
```

第四条在管理器侧：版本显示 `32715` / UAPI `6`，没有“需要更新内核”。

## 11 秒是怎么测的

端到端计时：从脚本启动到最后一步收尾完成。想拿到可比的数字，注意三件事。

**① 等系统稳下来再测。** 开机初期时钟会跳，脚本里的 `now_ms` 立刻就会算错 —— 早期量到过
“释放载荷 -902 ms”这种负数，纯粹是时钟源还没定。等 `uptime` 过 60 秒再开始。

**② 同一状态连续跑两次，看第二次。** 第一次跑会带上文件缓存、SELinux 策略未命中等一次性开销。
第二次才是稳定的数。

**③ 出现异常先怀疑测量，不要怀疑代码。**

这条是踩过的：某次改完模块，量到 13 秒，于是归因到“UAPI6 新增代码导致变慢”，还算了 `.text` 增加了
1336 字节、重定位多了 404 条当作证据。后来复测回到 11 秒 —— 那 2 秒是当时环境干扰，代码没问题。

在 4 万多重定位、10.5 MB 解包的基数上，那点增量根本不会变成 2 秒。**先复测，再归因。**

## 槽位：为什么有时候必须重启

每次喷射要选一个“槽位”（rvec 里的落点偏移），成功一次就消耗一个。脚本按类型给了备选序列：

| 类型 | 备选槽位 |
|---|---|
| `selinux` | `0x240 0x440 0x0c0 0x040 0x6c0 0x740` |
| `cred` | `0x680 0x700 0x740 0x6c0 0x780 0x540` |

用过的记录在 `/data/local/tmp/.ksu_slots`，脚本重启后仍然认得（这就是“槽位用尽，先重启”的由来）。

另一个约束更重要：**一个进程只打一个目标。** 在同一个进程里连着做两次 chain walk，会崩在
`rt_mutex_adjust_prio_chain` 里的 `BUG_ON(w->lock != lock)`。所以 `selinux` 和 `sig` 是两次独立执行，
进程用完就退出。

## 失败长什么样

| 现象 | 含义 | 该怎么办 |
|---|---|---|
| 输出 `VERDICT(...): ... (unchanged)` | miss，目标没被写进去 | 重跑，会换下一个槽位 |
| 卡住后超时 | 时序没踩上 | 重跑 |
| `sig_enforce` 栏拒绝 | 严格模式下读不出来 | 先关 SELinux 再重试 |
| 直接黑屏重启 | panic（`panic_on_oops=1`） | 等起来，重跑；如果反复，看 `/proc/last_kmsg` |
| `insmod_rc != 0` | 模块没装进去 | 不要反复试，先看 `dmesg` 的符号报错 |

**miss 不 panic，panic 一定重启。** 这两个待遇完全不同，脚本里的分支也是按这个设计的。

`insmod` 之前必须先确认 `sig_enforce` 已经是 `N`，否则一装就 Oops。这一步是硬性闸门，不确认就不装。

## 回滚

要回滚，得留着两样东西：**旧版 `ksu` 脚本**和**旧版模块**。本仓库只发当前这一版，旧版需要自己留底。

```sh
# 1) 脚本回滚
cp /path/to/old_ksu /data/local/tmp/ksu
chmod 755 /data/local/tmp/ksu

# 2) 模块回滚（如果只换了载荷里的 ko）
sh tools/repack.sh main/ksu old_ksu_raw.ko dl/ksu_raw.ko ksu_old
cp ksu_old /data/local/tmp/ksu && chmod 755 /data/local/tmp/ksu

# 3) 重启后验证
sh /data/local/tmp/ksu
```

旧版参考值（32680 / UAPI 5）：`ksu_raw.ko` md5 `14d9d0d0…`。

### 回滚必须重启之后才验证

模块已经加载时，脚本会走“跳过利用”的分支，直接进收尾 —— 它**不会重新 `insmod`**。
所以这个状态下跑脚本，看到的一切正常都说明不了任何问题，也验证不了回滚是否生效。

## 别做的四件事

1. **别在模块已加载时测耗时**，那个数字没有意义。
2. **别杀那个 `uid=0` 常驻进程**，它一死 `init_cred` 引用计数归零，直接 panic。
3. **别在 Permissive 窗口里顺手做别的事**，检测逻辑会在 syscall 出口重读 `uid`，判定被提权后杀整个进程组。
4. **别拿这份产物上别的机型**，vermagic 和栈偏移都是这台机器的。