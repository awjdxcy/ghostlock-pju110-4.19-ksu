#!/system/bin/sh
# pack.sh —— 把 main/ksu.sh 和四件载荷重新组装成一个可执行的 `ksu`
#
#   用法: sh tools/pack.sh <载荷目录> [输出文件]
#   载荷目录里要有: lt/gl_v112  dl/ksu_raw.ko  dl/libksud.so  dl/allowlist.bin
#   默认输出 main/ksu.new
#
#   先说清楚结果的性质：
#     头部逐字节相同、四件 md5 相同 —— 这两条是确定的。
#     整文件 md5 不保证与仓库里的 main/ksu 一致，因为 tar 条目顺序、
#     gzip 压缩参数都会影响字节流。判等请看「头部 md5 + 四件 md5」，
#     不要比整文件 md5。

set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIR=${1:-}
OUT=${2:-$ROOT/main/ksu.new}
HDR=$ROOT/main/ksu.sh

[ -n "$DIR" ] || { echo "用法: sh tools/pack.sh <载荷目录> [输出文件]"; exit 2; }
[ -f "$HDR" ] || { echo "缺少 $HDR"; exit 2; }

for f in lt/gl_v112 dl/ksu_raw.ko dl/libksud.so dl/allowlist.bin; do
    [ -f "$DIR/$f" ] || { echo "缺少载荷: $DIR/$f"; exit 2; }
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/pack_XXXXXX" 2>/dev/null) || { echo "建不了临时目录"; exit 2; }
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/p/lt" "$TMP/p/dl"
cp "$DIR/lt/gl_v112"      "$TMP/p/lt/gl_v112"
cp "$DIR/dl/ksu_raw.ko"   "$TMP/p/dl/ksu_raw.ko"
cp "$DIR/dl/libksud.so"   "$TMP/p/dl/libksud.so"
cp "$DIR/dl/allowlist.bin" "$TMP/p/dl/allowlist.bin"
chmod 755 "$TMP/p/lt/gl_v112"

( cd "$TMP/p" && tar czf "$TMP/payload.tgz" lt dl ) || { echo "打包失败"; exit 3; }

cat "$HDR" "$TMP/payload.tgz" > "$OUT" || { echo "写入失败"; exit 3; }
chmod 755 "$OUT"

HS=$(wc -c < "$HDR")
OFF=$((HS + 1))
SEEN=$(awk 'index($0,"PAYLOAD_OFFSET=")==1{sub(/^PAYLOAD_OFFSET=/,"");print;exit}' "$HDR")

echo "头部          : $HS 字节"
echo "脚本里的偏移  : ${SEEN:-读不出}"
echo "实际偏移      : $OFF"
if [ "$SEEN" = "$OFF" ]; then
    echo "[OK]   偏移自洽"
else
    echo "[WARN] 偏移不一致，运行时会切错位置"
fi
echo "输出          : $OUT（$(wc -c < "$OUT") 字节）"
echo
echo "下一步: sh tools/verify.sh   （核四件 md5）"