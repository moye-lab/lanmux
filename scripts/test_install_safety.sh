#!/usr/bin/env bash
# LanMux — 安装/卸载安全簇函数级测试（H-14 / L-25 / L-26 / D-07）。
#
# 只做函数级隔离验证：从 install.sh / uninstall.sh 原文件抽取函数定义
# （awk 按 ^name() { 到行首 } 截取），在隔离环境 source 后跑；绝不整
# 脚本执行 install.sh / uninstall.sh（它们从未在沙箱端到端执行过，
# 真机端到端验证仍需另做）。
#
# 用法：bash scripts/test_install_safety.sh
#   退出码 0 = 全部通过；1 = 有 FAIL。SKIP 只用于非 root 下跑不了的
#   /opt/lanmux 删除放行用例（沙箱以 root 跑时不应出现 SKIP）。
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd -P)"
INSTALL_SH="$REPO_ROOT/install.sh"
UNINSTALL_SH="$REPO_ROOT/uninstall.sh"

N_PASS=0
N_FAIL=0
N_SKIP=0

# ---- 被测函数依赖的桩与全局变量（先定义，再 source 抽取的函数）----
log_info() { echo "[..] $*"; }
log_ok() { echo "[ OK ] $*"; }
log_warn() { echo "[WARN] $*" >&2; }
die() { echo "[ERROR] $*" >&2; exit 1; }

INSTALL_DIR="/opt/lanmux"
DATA_DIR="/etc/lanmux"
SYSTEMD_DIR="/etc/systemd/system"
LANMUX_ENV="/etc/lanmux/lanmux.env"
FRESH_INSTALL="0"
HAVE_EXISTING_INSTALL=0
PASSWORDS_FROM_FILE=""
_PARSE_WARNED_FILE=""
ADMIN_PASSWORD=""
SS_PASSWORD=""
MIHOMO_SECRET=""
LAST_BACKUP_DIR=""

FIXTURES="$(mktemp -d)"
EXTRACT_DIR="$(mktemp -d)"
OPT_FIXTURE_BASE=""
OPT_FIXTURE_CREATED=0

cleanup() {
    if [ -n "$OPT_FIXTURE_BASE" ] && [ -d "$OPT_FIXTURE_BASE" ]; then
        rm -rf -- "$OPT_FIXTURE_BASE"
    fi
    if [ "$OPT_FIXTURE_CREATED" -eq 1 ] && [ -d "/opt/lanmux" ]; then
        rmdir /opt/lanmux 2>/dev/null || true
    fi
    rm -rf -- "$FIXTURES" "$EXTRACT_DIR"
}
trap cleanup EXIT

# ---- 抽取函数 ----
extract_fn() {
    # extract_fn <file> <name> — 打印该文件的顶层函数定义全文。
    awk "/^$2\\(\\) \\{/,/^}/" "$1"
}

{
    grep '^LANMUX_ALLOWED_RM_ROOTS=' "$INSTALL_SH"
    for f in validate_rm_target safe_rm_rf require_lanmux_marker backup_data_dir \
        check_fresh_install_confirm validate_install_paths \
        _env_inner_is_clean _env_unescape_dquote parse_env_file_value \
        lanmux_env_number lanmux_env_value \
        check_env_file_perms load_install_env_file warn_env_passwords; do
        extract_fn "$INSTALL_SH" "$f"
    done
} > "$EXTRACT_DIR/fns.sh"
# shellcheck disable=SC1090
. "$EXTRACT_DIR/fns.sh"

# ---- 断言小工具 ----
pass() { N_PASS=$((N_PASS + 1)); echo "[PASS] $*"; }
fail() { N_FAIL=$((N_FAIL + 1)); echo "[FAIL] $*"; }
skip() { N_SKIP=$((N_SKIP + 1)); echo "[SKIP] $*"; }

assert_eq() {
    # assert_eq <name> <got> <want>
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1：得到 [$2]，期望 [$3]"
    fi
}

expect_reject() {
    # expect_reject <name> <command...> — 子 shell 里跑，应非零退出（die）。
    local name="$1"
    shift
    if ( "$@" ) >/dev/null 2>&1; then
        fail "$name：应拒绝却放行了"
    else
        pass "$name"
    fi
}

expect_allow() {
    # expect_allow <name> <command...> — 子 shell 里跑，应零退出。
    local name="$1"
    shift
    if ( "$@" ) >/dev/null 2>&1; then
        pass "$name"
    else
        fail "$name：应放行却拒绝了"
    fi
}

# ==================================================================
# 1) H-14：validate_rm_target 白名单
# ==================================================================
echo "== 1) validate_rm_target 白名单 =="
for bad in "" "/" "/etc" "/opt" "/usr" "/home" "/root" "/var" "/var/lib" \
    "/etc/systemd" "/etc/systemd/system" "$HOME" "/opt/lanmux-test" \
    "/opt/lanmux/../etc" "/opt/lanmux/.." "../etc" "/etc/lanmux/../../etc" \
    "/etc/lanmuxx" "/tmp" "/tmp/lanmux" "/srv" "/boot"; do
    expect_reject "拒绝删除目标：${bad:-<空>}" validate_rm_target "$bad"
done
for good in "/opt/lanmux" "/etc/lanmux" "/var/lib/lanmux" "/opt/lanmux/backend" \
    "/etc/lanmux/ui" "/opt/lan-proxy-hub" "/etc/lan-proxy-hub" \
    "/opt/fenliu" "/etc/fenliu" "/opt/lanmux/" "/etc/lanmux/config.yaml"; do
    expect_allow "放行删除目标：$good" validate_rm_target "$good"
done

# ==================================================================
# 2) H-14：safe_rm_rf 实删（仅 root 跑 /opt/lanmux 夹具）
# ==================================================================
echo "== 2) safe_rm_rf 实删 =="
if [ "$(id -u)" -ne 0 ]; then
    skip "safe_rm_rf 放行实删（非 root，无 /opt 写权限）"
    skip "safe_rm_rf 符号链接拒绝（非 root）"
else
    if [ ! -d "/opt/lanmux" ]; then
        mkdir -p /opt/lanmux
        OPT_FIXTURE_CREATED=1
    fi
    OPT_FIXTURE_BASE="/opt/lanmux/test-install-safety-$$"
    mkdir -p "$OPT_FIXTURE_BASE/keep" "$OPT_FIXTURE_BASE/drop/sub"
    echo x > "$OPT_FIXTURE_BASE/keep/keep.txt"
    echo x > "$OPT_FIXTURE_BASE/drop/sub/victim.txt"
    if ( safe_rm_rf "$OPT_FIXTURE_BASE/drop" ) >/dev/null 2>&1 \
        && [ ! -e "$OPT_FIXTURE_BASE/drop" ] \
        && [ -f "$OPT_FIXTURE_BASE/keep/keep.txt" ]; then
        pass "safe_rm_rf 放行 /opt/lanmux 子目录并只删目标"
    else
        fail "safe_rm_rf 放行 /opt/lanmux 子目录并只删目标"
    fi
    # 拒绝：/tmp 下的目录必须还在
    mkdir -p "$FIXTURES/reject-me"
    echo x > "$FIXTURES/reject-me/f.txt"
    expect_reject "safe_rm_rf 拒绝 /tmp 下目录" safe_rm_rf "$FIXTURES/reject-me"
    if [ -f "$FIXTURES/reject-me/f.txt" ]; then
        pass "被拒绝的目标原样保留"
    else
        fail "被拒绝的目标原样保留"
    fi
    # 拒绝：符号链接本身（指到 /tmp）与允许根下的指外链接
    ln -s "$FIXTURES/reject-me" "$OPT_FIXTURE_BASE/link-out"
    expect_reject "safe_rm_rf 拒绝符号链接本身" safe_rm_rf "$OPT_FIXTURE_BASE/link-out"
    if [ -L "$OPT_FIXTURE_BASE/link-out" ] && [ -f "$FIXTURES/reject-me/f.txt" ]; then
        pass "被拒绝的符号链接与指到内容原样保留"
    else
        fail "被拒绝的符号链接与指到内容原样保留"
    fi
    mkdir -p "$OPT_FIXTURE_BASE/real"
    ln -s /etc "$OPT_FIXTURE_BASE/real/evil"
    expect_reject "safe_rm_rf 拒绝允许根下指到 /etc 的链接" safe_rm_rf "$OPT_FIXTURE_BASE/real/evil"
    if [ -d /etc ] && [ -L "$OPT_FIXTURE_BASE/real/evil" ]; then
        pass "/etc 未被误删"
    else
        fail "/etc 未被误删"
    fi
fi

# ==================================================================
# 3) H-14：require_lanmux_marker 标记校验
# ==================================================================
echo "== 3) require_lanmux_marker 标记校验 =="
M1="$FIXTURES/marker-empty"
M2="$FIXTURES/marker-random"
M3="$FIXTURES/marker-db"
M4="$FIXTURES/marker-cfg"
mkdir -p "$M1" "$M2" "$M3" "$M4"
echo x > "$M2/random.txt"
echo x > "$M3/lanmux.db"
echo x > "$M4/config.yaml"
expect_allow "标记校验：不存在的目录放行" require_lanmux_marker "$FIXTURES/marker-none" lanmux.db
expect_allow "标记校验：空目录放行" require_lanmux_marker "$M1" lanmux.db config.yaml
expect_reject "标记校验：非空无标记拒绝" require_lanmux_marker "$M2" lanmux.env lanmux.db config.yaml
expect_allow "标记校验：含 lanmux.db 放行" require_lanmux_marker "$M3" lanmux.env lanmux.db config.yaml
expect_allow "标记校验：含 config.yaml 放行" require_lanmux_marker "$M4" lanmux.env lanmux.db config.yaml
echo x > "$FIXTURES/not-a-dir"
expect_reject "标记校验：非目录拒绝" require_lanmux_marker "$FIXTURES/not-a-dir" lanmux.db

# ==================================================================
# 4) H-14：validate_install_paths 路径覆盖校验
# ==================================================================
echo "== 4) validate_install_paths 路径覆盖校验 =="
( INSTALL_DIR="/etc" DATA_DIR="/etc/lanmux" SYSTEMD_DIR="/etc/systemd/system" validate_install_paths ) >/dev/null 2>&1 \
    && fail "路径覆盖：INSTALL_DIR=/etc 应拒绝" || pass "路径覆盖：INSTALL_DIR=/etc 应拒绝"
( INSTALL_DIR="/opt/lanmux-test" DATA_DIR="/etc/lanmux" SYSTEMD_DIR="/etc/systemd/system" validate_install_paths ) >/dev/null 2>&1 \
    && fail "路径覆盖：INSTALL_DIR=/opt/lanmux-test 应拒绝（边界）" || pass "路径覆盖：INSTALL_DIR=/opt/lanmux-test 应拒绝（边界）"
( INSTALL_DIR="/opt/lanmux" DATA_DIR="/home/x" SYSTEMD_DIR="/etc/systemd/system" validate_install_paths ) >/dev/null 2>&1 \
    && fail "路径覆盖：DATA_DIR=/home/x 应拒绝" || pass "路径覆盖：DATA_DIR=/home/x 应拒绝"
( INSTALL_DIR="/opt/lanmux" DATA_DIR="/etc/lanmux" SYSTEMD_DIR="/tmp" validate_install_paths ) >/dev/null 2>&1 \
    && fail "路径覆盖：SYSTEMD_DIR=/tmp 应拒绝" || pass "路径覆盖：SYSTEMD_DIR=/tmp 应拒绝"
( INSTALL_DIR="/opt/lanmux" DATA_DIR="/etc/lanmux" SYSTEMD_DIR="/etc/systemd/system" validate_install_paths ) >/dev/null 2>&1 \
    && pass "路径覆盖：默认三路径放行" || fail "路径覆盖：默认三路径放行"
( INSTALL_DIR="/opt/lanmux/custom" DATA_DIR="/var/lib/lanmux" SYSTEMD_DIR="/etc/systemd/system" validate_install_paths ) >/dev/null 2>&1 \
    && pass "路径覆盖：允许根下的子路径放行" || fail "路径覆盖：允许根下的子路径放行"

# ==================================================================
# 5) L-25：白名单解析（绝不执行）
# ==================================================================
echo "== 5) parse_env_file_value 白名单解析 =="
PWNED="/tmp/install-safety-pwned-$$"
rm -f "$PWNED"

# 5a 正常行：env_quote 产物（转义还原）与各引号形式
printf '%s\n' \
    'ADMIN_PASSWORD="a\"b\\c\$d"' \
    'MIHOMO_SECRET="pa\$\$word"' \
    "SS_PASSWORD='plain-pass-123'" \
    'LANMUX_WEB_PORT="8086"' \
    'LANMUX_LAN_IP=10.0.0.2' \
    '# 注释行' \
    '' \
    'export LANMUX_SS_PORT="10001"' \
    > "$FIXTURES/env-good"
assert_eq "解析：双引号转义还原" "$(parse_env_file_value "$FIXTURES/env-good" ADMIN_PASSWORD)" 'a"b\c$d'
assert_eq "解析：转义 \$ 还原" "$(parse_env_file_value "$FIXTURES/env-good" MIHOMO_SECRET)" 'pa$$word'
assert_eq "解析：单引号字面" "$(parse_env_file_value "$FIXTURES/env-good" SS_PASSWORD)" 'plain-pass-123'
assert_eq "解析：端口数字" "$(parse_env_file_value "$FIXTURES/env-good" LANMUX_WEB_PORT)" '8086'
assert_eq "解析：裸值" "$(parse_env_file_value "$FIXTURES/env-good" LANMUX_LAN_IP)" '10.0.0.2'
assert_eq "解析：export 前缀" "$(parse_env_file_value "$FIXTURES/env-good" LANMUX_SS_PORT)" '10001'
assert_eq "解析：不存在的键为空" "$(parse_env_file_value "$FIXTURES/env-good" NO_SUCH_KEY)" ''
assert_eq "解析：不存在的文件为空" "$(parse_env_file_value "$FIXTURES/env-nope" ADMIN_PASSWORD)" ''
# 双引号内含 ! 与 ;（合法密码字符，必须放行）
printf '%s\n' 'ADMIN_PASSWORD="p@ss!word;123"' > "$FIXTURES/env-punct"
assert_eq "解析：引号内 ! 与 ; 放行" "$(parse_env_file_value "$FIXTURES/env-punct" ADMIN_PASSWORD)" 'p@ss!word;123'
# 重复键：后值胜出（与 source 一致）
printf '%s\n' 'ADMIN_PASSWORD="first"' 'ADMIN_PASSWORD="second"' > "$FIXTURES/env-dup"
assert_eq "解析：重复键后值胜出" "$(parse_env_file_value "$FIXTURES/env-dup" ADMIN_PASSWORD)" 'second'
# CRLF 行尾
printf 'ADMIN_PASSWORD="crlf-ok"\r\n' > "$FIXTURES/env-crlf"
assert_eq "解析：CRLF 行尾" "$(parse_env_file_value "$FIXTURES/env-crlf" ADMIN_PASSWORD)" 'crlf-ok'

# 5b 毒行：必须拒绝整个文件，且绝不执行其中的命令替换
printf '%s\n' \
    "ADMIN_PASSWORD=\"\$(touch $PWNED)\"" \
    'SS_PASSWORD="ok123456"' \
    > "$FIXTURES/env-poison-dollar"
assert_eq "解析：含 \$(...) 的行整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-poison-dollar" SS_PASSWORD)" ''
if [ ! -e "$PWNED" ]; then pass "解析：命令替换未被执行"; else fail "解析：命令替换未被执行（$PWNED 已生成！）"; fi
printf '%s\n' 'ADMIN_PASSWORD="`touch /tmp/install-safety-pwned-x`"' 'SS_PASSWORD="ok123456"' > "$FIXTURES/env-poison-btick"
assert_eq "解析：含反引号的行整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-poison-btick" SS_PASSWORD)" ''
# 毒行在别的键上也要污染整个文件
printf '%s\n' 'ADMIN_PASSWORD="ok123456"' "SS_PASSWORD=\"\$(touch $PWNED)\"" > "$FIXTURES/env-poison-other"
assert_eq "解析：他键毒行同样整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-poison-other" ADMIN_PASSWORD)" ''
if [ ! -e "$PWNED" ]; then pass "解析：他键命令替换未被执行"; else fail "解析：他键命令替换未被执行"; fi
# 其它畸形行
printf '%s\n' 'echo hacked' 'ADMIN_PASSWORD="ok"' > "$FIXTURES/env-badline"
assert_eq "解析：非 KEY=VALUE 行整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-badline" ADMIN_PASSWORD)" ''
printf '%s\n' 'lowercase_key="x"' 'ADMIN_PASSWORD="ok"' > "$FIXTURES/env-badkey"
assert_eq "解析：小写键名整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-badkey" ADMIN_PASSWORD)" ''
printf '%s\n' 'ADMIN_PASSWORD="unterminated' > "$FIXTURES/env-unterm"
assert_eq "解析：双引号未闭合整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-unterm" ADMIN_PASSWORD)" ''
printf '%s\n' 'ADMIN_PASSWORD=abc;def' > "$FIXTURES/env-baremeta"
assert_eq "解析：裸值含 ; 整文件拒绝" "$(parse_env_file_value "$FIXTURES/env-baremeta" ADMIN_PASSWORD)" ''
printf '%s\n' 'ADMIN_PASSWORD="a${HOME}b"' > "$FIXTURES/env-varsub"
assert_eq '解析：双引号内未转义 ${} 整文件拒绝' "$(parse_env_file_value "$FIXTURES/env-varsub" ADMIN_PASSWORD)" ''

# 5c lanmux_env_value / lanmux_env_number 经解析器走通
LANMUX_ENV="$FIXTURES/env-good"
assert_eq "lanmux_env_value：读密码" "$(lanmux_env_value ADMIN_PASSWORD)" 'a"b\c$d'
assert_eq "lanmux_env_value：非密码键为空" "$(lanmux_env_value LANMUX_WEB_PORT)" ''
LANMUX_ENV="$FIXTURES/env-good"
assert_eq "lanmux_env_number：读端口" "$(lanmux_env_number LANMUX_WEB_PORT)" '8086'
printf '%s\n' 'LANMUX_WEB_PORT="8086x"' > "$FIXTURES/env-badport"
LANMUX_ENV="$FIXTURES/env-badport"
assert_eq "lanmux_env_number：非纯数字为空" "$(lanmux_env_number LANMUX_WEB_PORT)" ''
LANMUX_ENV="/etc/lanmux/lanmux.env"

# ==================================================================
# 6) L-26：密码文件加载与权限
# ==================================================================
echo "== 6) load_install_env_file 密码文件 =="
printf '%s\n' "ADMIN_PASSWORD='file-admin-123'" 'SS_PASSWORD="file-ss-456"' "MIHOMO_SECRET='file-secret-789'" > "$FIXTURES/install-600.env"
chmod 600 "$FIXTURES/install-600.env"
printf '%s\n' "ADMIN_PASSWORD='wide-admin'" > "$FIXTURES/install-644.env"
chmod 644 "$FIXTURES/install-644.env"
printf '%s\n' "ADMIN_PASSWORD='ro-admin'" > "$FIXTURES/install-400.env"
chmod 400 "$FIXTURES/install-400.env"

LANMUX_INSTALL_ENV_FILE="$FIXTURES/install-644.env"
expect_reject "密码文件：644 权限拒绝" load_install_env_file
LANMUX_INSTALL_ENV_FILE="$FIXTURES/install-missing.env"
expect_reject "密码文件：不存在拒绝" load_install_env_file
LANMUX_INSTALL_ENV_FILE="$FIXTURES/install-400.env"
ADMIN_PASSWORD=""; SS_PASSWORD=""; MIHOMO_SECRET=""; PASSWORDS_FROM_FILE=""
load_install_env_file >/dev/null 2>&1
assert_eq "密码文件：400 可读且加载" "$ADMIN_PASSWORD" "ro-admin"
LANMUX_INSTALL_ENV_FILE="$FIXTURES/install-600.env"
ADMIN_PASSWORD="env-admin-old"; SS_PASSWORD=""; MIHOMO_SECRET=""; PASSWORDS_FROM_FILE=""
load_install_env_file >/dev/null 2>&1
assert_eq "密码文件：ADMIN_PASSWORD 来自文件（覆盖环境变量）" "$ADMIN_PASSWORD" "file-admin-123"
assert_eq "密码文件：SS_PASSWORD 来自文件" "$SS_PASSWORD" "file-ss-456"
assert_eq "密码文件：MIHOMO_SECRET 来自文件" "$MIHOMO_SECRET" "file-secret-789"
ok_from_file=1
for kk in ADMIN_PASSWORD SS_PASSWORD MIHOMO_SECRET; do
    case " $PASSWORDS_FROM_FILE " in
        *" $kk "*) ;;
        *) ok_from_file=0 ;;
    esac
done
if [ "$ok_from_file" -eq 1 ]; then
    pass "密码文件：三键均记为来自文件"
else
    fail "密码文件：三键均记为来自文件（得到 [$PASSWORDS_FROM_FILE]）"
fi
# 环境变量密码告警：全来自文件时不告警；有来自环境变量时告警并点名
if [ -z "$(warn_env_passwords 2>&1)" ]; then pass "环境变量密码告警：全来自文件时静默"; else fail "环境变量密码告警：全来自文件时静默"; fi
PASSWORDS_FROM_FILE=""
ADMIN_PASSWORD=""; MIHOMO_SECRET=""
SS_PASSWORD="env-ss-password"
if warn_env_passwords 2>&1 | grep -q "SS_PASSWORD"; then pass "环境变量密码告警：环境变量来源告警并点名"; else fail "环境变量密码告警：环境变量来源告警并点名"; fi
LANMUX_INSTALL_ENV_FILE=""
ADMIN_PASSWORD=""; SS_PASSWORD=""; MIHOMO_SECRET=""; PASSWORDS_FROM_FILE=""

# ==================================================================
# 7) D-07：FRESH_INSTALL 二次确认门 + 清空前备份
# ==================================================================
echo "== 7) check_fresh_install_confirm + backup_data_dir =="
FRESH_INSTALL=1; HAVE_EXISTING_INSTALL=1
unset LANMUX_FRESH_INSTALL_CONFIRM
expect_reject "二次确认：无 CONFIRM 时拒绝清空" check_fresh_install_confirm
LANMUX_FRESH_INSTALL_CONFIRM=0
expect_reject "二次确认：CONFIRM=0 时拒绝清空" check_fresh_install_confirm
LANMUX_FRESH_INSTALL_CONFIRM=1
expect_allow "二次确认：CONFIRM=1 时放行" check_fresh_install_confirm
FRESH_INSTALL=0; HAVE_EXISTING_INSTALL=1
unset LANMUX_FRESH_INSTALL_CONFIRM
expect_allow "二次确认：FRESH_INSTALL=0 时放行" check_fresh_install_confirm
FRESH_INSTALL=1; HAVE_EXISTING_INSTALL=0
expect_allow "二次确认：无已有安装时放行" check_fresh_install_confirm
unset LANMUX_FRESH_INSTALL_CONFIRM
FRESH_INSTALL=0; HAVE_EXISTING_INSTALL=0

SRC="$FIXTURES/backup-src"
mkdir -p "$SRC/ui"
echo "db-content" > "$SRC/lanmux.db"
echo "cfg-content" > "$SRC/config.yaml"
echo "ui-content" > "$SRC/ui/index.html"
LAST_BACKUP_DIR="sentinel"
backup_data_dir "$SRC" >/dev/null 2>&1
if [ -n "$LAST_BACKUP_DIR" ] && [ -d "$LAST_BACKUP_DIR" ] \
    && [ "$(cat "$LAST_BACKUP_DIR/lanmux.db")" = "db-content" ] \
    && [ "$(cat "$LAST_BACKUP_DIR/ui/index.html")" = "ui-content" ] \
    && [ -f "$SRC/lanmux.db" ]; then
    pass "清空前备份：备份内容一致且源目录 untouched"
else
    fail "清空前备份：备份内容一致且源目录 untouched（LAST_BACKUP_DIR=[$LAST_BACKUP_DIR]）"
fi
case "$LAST_BACKUP_DIR" in
    *-backup-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]*)
        pass "清空前备份：备份目录带时间戳"
        ;;
    *)
        fail "清空前备份：备份目录带时间戳（得到 [$LAST_BACKUP_DIR]）"
        ;;
esac
LAST_BACKUP_DIR="sentinel"
backup_data_dir "$FIXTURES/backup-none" >/dev/null 2>&1
assert_eq "清空前备份：源不存在时直接返回" "$LAST_BACKUP_DIR" "sentinel"

# ==================================================================
# 8) 一致性：install.sh 与 uninstall.sh 的共享函数同一份
# ==================================================================
echo "== 8) 两脚本共享函数一致性 =="
for f in validate_rm_target safe_rm_rf require_lanmux_marker validate_install_paths; do
    extract_fn "$INSTALL_SH" "$f" | sed -e 's/安装开始前做/开始前做/' -e 's/卸载开始前做/开始前做/' > "$EXTRACT_DIR/a.txt"
    extract_fn "$UNINSTALL_SH" "$f" | sed -e 's/安装开始前做/开始前做/' -e 's/卸载开始前做/开始前做/' > "$EXTRACT_DIR/b.txt"
    if diff -q "$EXTRACT_DIR/a.txt" "$EXTRACT_DIR/b.txt" >/dev/null; then
        pass "共享函数一致：$f"
    else
        fail "共享函数一致：$f（两脚本已漂移）"
    fi
done

# ==================================================================
# 9) 静态检查
# ==================================================================
echo "== 9) 静态检查 =="
if bash -n "$INSTALL_SH" && bash -n "$UNINSTALL_SH"; then
    pass "bash -n：install.sh 与 uninstall.sh 语法通过"
else
    fail "bash -n：install.sh 与 uninstall.sh 语法通过"
fi
if grep -qF '. "$LANMUX_ENV"' "$INSTALL_SH"; then
    fail "install.sh 不再 source lanmux.env"
else
    pass "install.sh 不再 source lanmux.env"
fi
if grep -q 'LANMUX_VERSION="1.0.2"' "$INSTALL_SH"; then
    pass "版本号已升：1.0.2"
else
    fail "版本号已升：1.0.2"
fi

echo ""
echo "结果：PASS=$N_PASS FAIL=$N_FAIL SKIP=$N_SKIP"
if [ "$N_FAIL" -ne 0 ]; then
    exit 1
fi
exit 0
