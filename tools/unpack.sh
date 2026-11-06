#!/system/bin/sh
# unpack.sh —— 把 main/ksu 尾部的载荷解出来，并核对 md5
#
#   用法: sh unpack.sh [ksu 文件] [输出目录]
#   默认: sh unpack.sh ksu ./payload
#
# 偏移不写死：从脚本体里读 PAYLOAD_OFFSET，再校验头部长度 = 偏移 - 1。

set -u
SELF=${1:-ksu}
OUT=${2:-./payload}

[ -f "$SELF" ] || { echo "找不到 $SELF"; exit 1; }

OFF=$(awk 'index($0,"PAYLOAD_OFFSET=")==1{sub(/^PAYLOAD_OFFSET=/,"");print;exit}' "$SELF" 2>/dev/null)
[ -n "$OFF" ] || { echo "读不出 PAYLOAD_OFFSET（这个文件不是自包含脚本？）"; exit 1; }

HEAD=$((OFF - 1))
echo "文件      : $SELF ($(wc -c < "$SELF") 字节)"
echo "偏移      : $OFF  → 头部应为 $HEAD 字节"

mkdir -p "$OUT" || exit 1
tail -c "+$OFF" "$SELF" | gzip -d | tar x -C "$OUT" 2>/dev/null
[ $? -eq 0 ] || { echo "解包失败"; exit 1; }

echo "---- 解出 ----"
for f in lt/gl_v112 dl/ksu_raw.ko dl/libksud.so dl/allowlist.bin; do
    if [ -f "$OUT/$f" ]; then
        printf '%-18s %10s  %s\n' "$f" "$(wc -c < "$OUT/$f")" "$(md5sum "$OUT/$f" | cut -d' ' -f1)"
    else
        printf '%-18s %10s  %s\n' "$f" "缺失" "-"
    fi
done

cat <<'EOF'
---- 对照（本机验证过的值）----
lt/gl_v112         870760  2c4717dc596daca084f7317250fc8765
dl/ksu_raw.ko     4697872  44608d0d3fa8777304a6be1af069ecb9
dl/libksud.so     4990848  b7b87ee9dc0e57a393a28d88055e06fa
dl/allowlist.bin      792  c4221d6f192bebe8639223513cf7ac00
EOF