#!/system/bin/sh
# verify.sh —— 把仓库里的产物一次性校验完
#
#   用法: sh verify.sh [仓库根目录]
#   在仓库根目录跑: sh tools/verify.sh
#
# 校验三件事：
#   1) main/ksu.sh 是否等于 main/ksu 的前 N 字节（可读副本不能和成品漂移）
#   2) main/ksu 的头部长度与 PAYLOAD_OFFSET 是否自洽
#   3) 载荷四件的 md5 是否等于本机验证过的值

set -u
ROOT=${1:-.}
KSU=$ROOT/main/ksu
HDR=$ROOT/main/ksu.sh
FAIL=0

say() { printf '%s\n' "$*"; }
ok()  { printf '  [OK]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL + 1)); }

say "===== 0) 可读头部与成品是否同步 ====="
if [ ! -f "$HDR" ]; then
    bad "缺少 $HDR"
elif [ ! -f "$KSU" ]; then
    bad "缺少 $KSU"
else
    HS=$(wc -c < "$HDR")
    H1=$(md5sum "$HDR" | cut -d' ' -f1)
    H2=$(head -c "$HS" "$KSU" | md5sum | cut -d' ' -f1)
    if [ "$H1" = "$H2" ]; then
        ok "main/ksu.sh 等于 main/ksu 前 $HS 字节（md5 $H1）"
    else
        bad "main/ksu.sh 与成品头部不一致（$H1 ≠ $H2）"
    fi
fi

say ""
say "===== 1) main/ksu 结构 ====="
if [ ! -f "$KSU" ]; then
    bad "缺少 $KSU"
else
    SIZE=$(wc -c < "$KSU")
    OFF=$(awk 'index($0,"PAYLOAD_OFFSET=")==1{sub(/^PAYLOAD_OFFSET=/,"");print;exit}' "$KSU" 2>/dev/null)
    say "  大小          : $SIZE"
    say "  PAYLOAD_OFFSET: ${OFF:-读不出}"
    if [ -n "$OFF" ]; then
        HEAD=$((OFF - 1))
        ACT=$(head -c "$HEAD" "$KSU" | wc -c)
        if [ "$ACT" -eq "$HEAD" ]; then ok "头部 $HEAD 字节完整"; else bad "头部长度 $ACT ≠ $HEAD"; fi
        if head -c "$HEAD" "$KSU" | sh -n 2>/dev/null; then ok "头部 shell 语法通过"; else bad "头部语法不通过"; fi
        say "  头部 md5      : $(head -c "$HEAD" "$KSU" | md5sum | cut -d' ' -f1)"
    fi
fi

say ""
say "===== 2) 载荷四件 md5 ====="
TMP=$(mktemp -d "${TMPDIR:-/tmp}/verify_XXXXXX" 2>/dev/null) || TMP=${TMPDIR:-/tmp}/verify_$$
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/p"
if [ -f "$KSU" ] && { tail -c +"${OFF:-17573}" "$KSU" | gzip -d | tar x -C "$TMP/p" 2>/dev/null; }; then
    check() {
        f=$1; want=$2
        if [ ! -f "$TMP/p/$f" ]; then bad "$f 缺失"; return; fi
        got=$(md5sum "$TMP/p/$f" | cut -d' ' -f1)
        if [ "$got" = "$want" ]; then ok "$f  $got"; else bad "$f  $got ≠ $want"; fi
    }
    check lt/gl_v112        2c4717dc596daca084f7317250fc8765
    check dl/ksu_raw.ko     44608d0d3fa8777304a6be1af069ecb9
    check dl/libksud.so     b7b87ee9dc0e57a393a28d88055e06fa
    check dl/allowlist.bin  c4221d6f192bebe8639223513cf7ac00
else
    bad "载荷解包失败"
fi

say ""
if [ "$FAIL" -eq 0 ]; then
    say "全部通过。"
else
    say "有 $FAIL 项不通过。"
    exit 1
fi