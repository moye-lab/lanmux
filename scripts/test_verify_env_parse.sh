#!/usr/bin/env bash
# LanMux — verify.sh env 解析测试（L-25）。
#
# verify.sh 不再 source lanmux.env：它内置了与 install.sh 逐字相同的
# 白名单解析器（parse_env_file_value），逐键读取。本测试验证：
#   1) 解析器副本与 install.sh 的逐字同步（diff 必须为空）；
#   2) 函数级：正常值、FENLIU_* 回落、毒行整文件拒绝且绝不执行；
#   3) 端到端：跑 verify.sh（无服务，本机检查全 FAIL，但退出码不影响
#      断言），验证文件值确实被读到、CLI 变量优先、毒文件被拒绝且
#      其中的命令替换未执行。
#
# 用法：bash scripts/test_verify_env_parse.sh
#   退出码 0 = 全部通过；1 = 有 FAIL。
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd -P)"
VERIFY_SH="$REPO_ROOT/scripts/verify.sh"
INSTALL_SH="$REPO_ROOT/install.sh"

N_PASS=0
N_FAIL=0

FIXTURES="$(mktemp -d)"
EXTRACT_DIR="$(mktemp -d)"
PWNED="/tmp/verify-env-pwned-$$"
rm -f "$PWNED"

cleanup() {
    rm -rf -- "$FIXTURES" "$EXTRACT_DIR" "$PWNED"
}
trap cleanup EXIT

pass() { N_PASS=$((N_PASS + 1)); echo "[PASS] $*"; }
fail() { N_FAIL=$((N_FAIL + 1)); echo "[FAIL] $*"; }

assert_eq() {
    # assert_eq <name> <got> <want>
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1：得到 [$2]，期望 [$3]"
    fi
}

assert_contains() {
    # assert_contains <name> <haystack> <needle>
    if printf '%s' "$2" | grep -qF "$3"; then
        pass "$1"
    else
        fail "$1：未找到 [$3]"
    fi
}

assert_not_contains() {
    # assert_not_contains <name> <haystack> <needle>
    if printf '%s' "$2" | grep -qF "$3"; then
        fail "$1：不应出现 [$3]"
    else
        pass "$1"
    fi
}

# ---- 抽取函数（与 test_install_safety.sh 同款 awk 截取） ----
extract_fn() {
    # extract_fn <file> <name> — 打印该文件的顶层函数定义全文。
    awk "/^$2\\(\\) \\{/,/^}/" "$1"
}

log_warn() { echo "[WARN] $*" >&2; }
_PARSE_WARNED_FILE=""

{
    for f in _env_inner_is_clean _env_unescape_dquote parse_env_file_value _env_first; do
        extract_fn "$VERIFY_SH" "$f"
    done
} > "$EXTRACT_DIR/verify-fns.sh"
# shellcheck disable=SC1090
. "$EXTRACT_DIR/verify-fns.sh"

echo "== 1) 解析器副本与 install.sh 逐字同步 =="
{
    for f in _env_inner_is_clean _env_unescape_dquote parse_env_file_value; do
        extract_fn "$INSTALL_SH" "$f"
    done
} > "$EXTRACT_DIR/install-fns.sh"
{
    for f in _env_inner_is_clean _env_unescape_dquote parse_env_file_value; do
        extract_fn "$VERIFY_SH" "$f"
    done
} > "$EXTRACT_DIR/verify-parser-fns.sh"
if diff -q "$EXTRACT_DIR/install-fns.sh" "$EXTRACT_DIR/verify-parser-fns.sh" >/dev/null; then
    pass "解析器三函数与 install.sh 逐字一致"
else
    fail "解析器三函数与 install.sh 不一致（改了一处必须同步另一处）"
    diff "$EXTRACT_DIR/install-fns.sh" "$EXTRACT_DIR/verify-parser-fns.sh" | head -20
fi

echo "== 2) 函数级：正常值与 FENLIU_* 回落 =="
printf '%s\n' \
    'MIHOMO_SECRET="file-secret-1"' \
    'ADMIN_PASSWORD="file-admin-1"' \
    'LANMUX_SS_PORT="18080"' \
    'LANMUX_MIXED_PORT="17890"' \
    'LANMUX_CONTROLLER_PORT="19090"' \
    'LANMUX_WEB_PORT="18086"' \
    'LANMUX_MIXED_AUTH_USER="fileuser"' \
    "LANMUX_MIXED_AUTH_PASS='filepass'" \
    > "$FIXTURES/env-good"
assert_eq "解析：MIHOMO_SECRET" "$(parse_env_file_value "$FIXTURES/env-good" MIHOMO_SECRET)" 'file-secret-1'
assert_eq "解析：ADMIN_PASSWORD" "$(parse_env_file_value "$FIXTURES/env-good" ADMIN_PASSWORD)" 'file-admin-1'
assert_eq "解析：SS 端口" "$(parse_env_file_value "$FIXTURES/env-good" LANMUX_SS_PORT)" '18080'
assert_eq "解析：单引号密码" "$(parse_env_file_value "$FIXTURES/env-good" LANMUX_MIXED_AUTH_PASS)" 'filepass'

printf '%s\n' 'FENLIU_SS_PORT="17070"' > "$FIXTURES/env-legacy"
assert_eq "回落：无 LANMUX_* 时取 FENLIU_SS_PORT" "$(_env_first "$FIXTURES/env-legacy" LANMUX_SS_PORT FENLIU_SS_PORT)" '17070'
assert_eq "回落：LANMUX_* 优先于 FENLIU_*" "$(_env_first "$FIXTURES/env-good" LANMUX_SS_PORT FENLIU_SS_PORT)" '18080'
assert_eq "回落：两键皆无为空" "$(_env_first "$FIXTURES/env-legacy" LANMUX_SS_PORT FENLIU_MIXED_PORT)" ''

echo "== 3) 函数级：毒行整文件拒绝，绝不执行 =="
printf '%s\n' \
    'MIHOMO_SECRET="should-not-apply"' \
    "LANMUX_SS_PORT=\"\$(touch \"$PWNED\")\"" \
    > "$FIXTURES/env-poison-dollar"
assert_eq "毒行：含 \$(...) 整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-poison-dollar" MIHOMO_SECRET)" ''
if [ ! -e "$PWNED" ]; then pass "毒行：命令替换未被执行"; else fail "毒行：命令替换未被执行（$PWNED 已生成！）"; fi
printf '%s\n' \
    'MIHOMO_SECRET="should-not-apply"' \
    'LANMUX_SS_PORT=`touch "$PWNED"`' \
    > "$FIXTURES/env-poison-btick"
assert_eq "毒行：含反引号整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-poison-btick" MIHOMO_SECRET)" ''
if [ ! -e "$PWNED" ]; then pass "毒行：反引号未被执行"; else fail "毒行：反引号未被执行（$PWNED 已生成！）"; fi

echo "== 4) 端到端：verify.sh 读文件值 / CLI 优先 / 毒文件拒绝 =="
# 无服务：检查全 FAIL 是预期的，只看输出里的端口与告警。env -i 隔离，
# 避免本 shell 的变量漏进被测脚本。
run_verify() {
    # run_verify <env-file> [extra env assignments...] — 输出记入 $1 文件
    local env_file="$1"; shift
    timeout 120 env -i PATH=/usr/bin:/bin HOME=/root \
        LANMUX_ENV_FILE="$env_file" "$@" \
        bash "$VERIFY_SH" 2>&1 || true
}

OUT="$(run_verify "$FIXTURES/env-good")"
assert_contains "端到端：文件 SS 端口 18080 被采用" "$OUT" "127.0.0.1:18080"
assert_not_contains "端到端：好文件不告警拒绝" "$OUT" "env 文件已拒绝解析"

OUT="$(run_verify "$FIXTURES/env-legacy")"
assert_contains "端到端：旧文件 FENLIU_SS_PORT 17070 被采用" "$OUT" "127.0.0.1:17070"

OUT="$(run_verify "$FIXTURES/env-good" LANMUX_SS_PORT=19090)"
assert_contains "端到端：CLI 端口 19090 优先于文件 18080" "$OUT" "127.0.0.1:19090"
assert_not_contains "端到端：CLI 优先时文件端口不出现" "$OUT" "127.0.0.1:18080"

rm -f "$PWNED"
OUT="$(run_verify "$FIXTURES/env-poison-dollar")"
assert_contains "端到端：毒文件告警拒绝解析" "$OUT" "env 文件已拒绝解析"
assert_contains "端到端：毒文件拒绝后 SS 端口回落默认 10001" "$OUT" "127.0.0.1:10001"
if [ ! -e "$PWNED" ]; then pass "端到端：毒文件命令替换未被执行"; else fail "端到端：毒文件命令替换未被执行（$PWNED 已生成！）"; fi

echo
echo "结果：PASS=$N_PASS FAIL=$N_FAIL"
[ "$N_FAIL" -eq 0 ]
