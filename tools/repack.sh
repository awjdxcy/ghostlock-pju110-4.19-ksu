#!/system/bin/sh
# repack.sh —— 替换 main/ksu 载荷里的单个文件，头部一字不动
#
#   用法: sh repack.sh <原 ksu> <新文件> <载荷内路径> [输出]
#   例:   sh repack.sh ksu ksu_raw.ko dl/ksu_raw.ko ksu_new
#         sh repack.sh ksu gl_v112    lt/gl_v112    ksu_new
#
# 为什么要这个脚本：
#   这个 ksu 是「脚本体 + gzip/tar 载荷」拼起来的单文件。运行时它会把载荷
#   解出来覆盖设备上的模块，所以只替换外部的 ksu_raw.ko 是没用的 —— 下次
#   运行又会被载荷写回去。要换东西必须换载荷本身。
#   而载荷起点由脚本体里的 PAYLOAD_OFFSET 决定，头部字节数必须严格保持
#   PAYLOAD_OFFSET-1，多一个少一个字节都会让偏移错位。

set -u
SRC=${1:-}
NEW=${2:-}
INNER=${3:-}
OUT=${4:-ksu_new}

[ -n "$SRC" ] && [ -n "$NEW" ] && [ -n "$INNER" ] || {
    echo "用法: sh repack.sh <原 ksu> <新文件> <载荷内路径> [输出]"; exit 1; }
[ -f "$SRC" ] && [ -f "$NEW" ] || { echo "文件不存在"; exit 1; }

OFF=$(awk 'index($0,"PAYLOAD_OFFSET=")==1{sub(/^PAYLOAD_OFFSET=/,"");print;exit}' "$SRC" 2>/dev/null)
[ -n "$OFF" ] || { echo "读不出 PAYLOAD_OFFSET"; exit 1; }
HEAD=$((OFF - 1))

TMP=$(mktemp -d "${TMPDIR:-/tmp}/repack_XXXXXX" 2>/dev/null) || TMP=${TMPDIR:-/tmp}/repack_$$
mkdir -p "$TMP/p" || { echo "工作目录建不了: $TMP"; exit 1; }
trap 'rm -rf "$TMP"' EXIT

head -c "$HEAD" "$SRC" > "$TMP/head.bin" || exit 1
[ "$(wc -c < "$TMP/head.bin")" -eq "$HEAD" ] || { echo "头部截取失败"; exit 1; }

tail -c "+$OFF" "$SRC" | gzip -d | tar x -C "$TMP/p" 2>/dev/null || { echo "原载荷解包失败"; exit 1; }

case "$INNER" in
    lt/*|dl/*) ;;
    *) echo "载荷内路径应以 lt/ 或 dl/ 开头"; exit 1 ;;
esac

cp -f "$NEW" "$TMP/p/$INNER" || { echo "覆盖 $INNER 失败"; exit 1; }

( cd "$TMP/p" && tar cf - lt dl 2>/dev/null | gzip -9 ) > "$TMP/payload.gz" || { echo "重打包失败"; exit 1; }

cat "$TMP/head.bin" "$TMP/payload.gz" > "$OUT" || exit 1
chmod 755 "$OUT"

echo "输入   : $SRC ($(wc -c < "$SRC") 字节)"
echo "替换   : $INNER  ←  $NEW"
echo "输出   : $OUT ($(wc -c < "$OUT") 字节)"
echo "头部   : $(wc -c < "$TMP/head.bin") 字节（应等于 $HEAD）"
echo "头 md5 : $(md5sum "$TMP/head.bin" | cut -d' ' -f1)"
echo "     原 : $(head -c "$HEAD" "$SRC" | md5sum | cut -d' ' -f1)"
echo
echo "自检：解包输出的载荷"
mkdir -p "$TMP/v"
tail -c "+$OFF" "$OUT" | gzip -d | tar x -C "$TMP/v" 2>/dev/null
for f in lt/gl_v112 dl/ksu_raw.ko dl/libksud.so dl/allowlist.bin; do
    [ -f "$TMP/v/$f" ] && printf '  %-18s %10s  %s\n' "$f" "$(wc -c < "$TMP/v/$f")" "$(md5sum "$TMP/v/$f" | cut -d' ' -f1)"
done
echo
echo "下一步：把 $OUT 推到设备 /data/local/tmp/ksu 并 chmod 755，重启后跑一次验证。"