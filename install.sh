#!/usr/bin/env bash
# LanMux — 二进制 + systemd 安装器（主推部署路径）。
#
# 用法（在仓库根目录执行）：
#   sudo bash install.sh                    # 交互式安装 / 升级
#   sudo bash install.sh --non-interactive  # 非交互式（全部取值于环境变量）
#   sudo bash install.sh --help
#
# 非交互安装（无人值守）：密码绝不要写进命令行（会进 shell history，
# 进程存活期间同用户经 /proc/<pid>/environ 也可见）。先把密码写进
# 一个仅属主可读的文件（600），再用 LANMUX_INSTALL_ENV_FILE 指给安装器：
#   git clone https://github.com/moye-lab/lanmux.git
#   cd lanmux
#   printf '%s\n' "ADMIN_PASSWORD='改成你的管理密码'" \
#     "SS_PASSWORD='改成你的SS密码'" \
#     "MIHOMO_SECRET='改成一串随机字串'" > /root/lanmux-install.env
#   chmod 600 /root/lanmux-install.env
#   sudo LANMUX_INSTALL_ENV_FILE=/root/lanmux-install.env bash install.sh --non-interactive
#   rm -f /root/lanmux-install.env
# 首选仍是交互安装（sudo bash install.sh）：安装器会提问并出打码确认页。
# 密码含单引号时改用双引号写那一行（ADMIN_PASSWORD="..."，双引号内的
# $、反引号、\ 需在前面加 \ 转义）；含 $( 或反引号的密码请走交互输入。
#
# 升级 = 重新跑一遍本脚本（节点、规则、设置、密码全部保留，只更新
# 程序、二进制与面板）。卸载见 uninstall.sh。
#
# 本脚本绝不碰：/etc/mihomo 与 mihomo 单元（用户旧 mihomo-gateway 的
# 东西）、docker。LanMux 用自己的名字与路径：
#   单元：lanmux-mihomo.service / lanmux-web.service
#   程序：/opt/lanmux/（后端、前端、venv、mihomo 二进制、metacubexd）
#   数据：/etc/lanmux/（config.yaml、lanmux.db、lanmux.env、geodata）
#   运行用户：lanmux（专用系统用户；两个 systemd 单元均以 User=lanmux
#   运行，数据目录 /etc/lanmux 属主为 lanmux，程序目录保持 root 属主只读）
#
# 环境变量（全部可选，未设置时走默认值或交互提问）：
#   LANMUX_NONINTERACTIVE=1        非交互模式
#   LANMUX_FRESH_INSTALL=1         强制全新安装（清空数据！）
#   LANMUX_FRESH_INSTALL_CONFIRM=1 全新安装的二次确认：与上一项同时设置才清空，
#                               缺了就拒绝清空并报错；交互模式下同样要求。
#                               清空前自动备份到带时间戳的兄弟目录。
#   LANMUX_INSTALL_ENV_FILE        密码文件路径（600 权限，含 ADMIN_PASSWORD /
#                               SS_PASSWORD / MIHOMO_SECRET 三行；替代命令行传密码）
#   ADMIN_PASSWORD              管理员密码（全新安装时预置；升级时忽略
#                               环境变量、继承现有 lanmux.env 里的值，改密码
#                               请登录面板后在设置里改；首选交互提问或密码文件，
#                               直接写命令行会进 shell history，见上）
#   MIHOMO_SECRET / SS_PASSWORD 同上：仅全新安装时生效；升级时优先读 DB，
#                               DB 没有则继承现有 lanmux.env
#   SS_CIPHER                   SS 加密方式（默认 aes-128-gcm）
#   LANMUX_LAN_IP                  宿主机局域网 IP（默认自动探测）
#   LANMUX_SS_PORT / LANMUX_MIXED_PORT / LANMUX_CONTROLLER_PORT / LANMUX_WEB_PORT
#                               四个端口（默认 10001 / 7890 / 9090 / 8086）
#   LANMUX_MIXED_AUTH_USER / LANMUX_MIXED_AUTH_PASS   Mixed 入口鉴权（可选）
#   LANMUX_EXTERNAL_UI             metacubexd 目录（默认自动填；设为 none 禁用）
#   MIHOMO_VERSION              mihomo 版本（默认 1.19.34）
#   METACUBEXD_VERSION          metacubexd 版本（默认 1.276.0）
#   MIHOMO_MIRROR / GEODATA_MIRROR  镜像前缀（如 https://gh-proxy.com），
#                               优先于内置镜像列表尝试
#   LANMUX_REFRESH_GEODATA=1       强制重下 geodata（默认已存在且非空则跳过）
#   LANMUX_INSTALL_DIR / LANMUX_DATA_DIR / LANMUX_SYSTEMD_DIR  路径覆盖（仅供测试）
#   PIP_INDEX_URL               pip 镜像源（网络慢时用，如清华源）
#
# 下载完整性（H-13）：mihomo / metacubexd / geodata 三路下载后一律按
# scripts/asset-checksums.sha256 里的固定 SHA256 强制校验，不匹配即
# 中止安装，已落盘的损坏文件会被删除重下。清单缺失或某资产无对应
# 哈希时同样中止（fail-closed），绝不跳过校验装下去。指定了未钉哈希
# 的 MIHOMO_VERSION / METACUBEXD_VERSION 也会在这一步被拒绝。
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

LANMUX_VERSION="1.0.2"
MIHOMO_VERSION="${MIHOMO_VERSION:-1.19.34}"
METACUBEXD_VERSION="${METACUBEXD_VERSION:-1.276.0}"
INSTALL_DIR="${LANMUX_INSTALL_DIR:-/opt/lanmux}"
DATA_DIR="${LANMUX_DATA_DIR:-/etc/lanmux}"
SYSTEMD_DIR="${LANMUX_SYSTEMD_DIR:-/etc/systemd/system}"
MIHOMO_BIN="$INSTALL_DIR/bin/mihomo"
# metacubexd 必须放在 mihomo 家目录（-d，即 $DATA_DIR）的子路径下，
# 否则 mihomo -t 直接报错 "path is not subpath of home directory or
# SAFE_PATHS"（真实 mihomo v1.19.34 实测；与 mihomo-gateway 的 /etc/mihomo/ui
# 约定一致）。所以 UI 默认在 $DATA_DIR/ui，而不是 $INSTALL_DIR 下。
UI_DIR="$DATA_DIR/ui"
VENV_DIR="$INSTALL_DIR/venv"
BACKEND_DIR="$INSTALL_DIR/backend"
LANMUX_ENV="$DATA_DIR/lanmux.env"
DB_PATH="$DATA_DIR/lanmux.db"
CONFIG_PATH="$DATA_DIR/config.yaml"

# 专用低权运行用户（H-15）：两个 systemd 单元均以 User=/Group=lanmux
# 运行；与 Docker 镜像内的 lanmux 用户同名同义，但 UID 各自由环境分配
# （容器内固定为 10001），两者不跨环境共用 UID。
LANMUX_USER="lanmux"

# 旧名残留（v0.9.0 改名前叫 LAN Proxy Hub）：迁移专用，见 migrate_legacy_install。
LEGACY_INSTALL_DIR="/opt/lan-proxy-hub"
LEGACY_DATA_DIR="/etc/lan-proxy-hub"

# 旧名残留（v1.0.0 改名前叫 Fenliu）：迁移专用，见 migrate_lanmux_install。
LEGACY_FENLIU_INSTALL_DIR="/opt/fenliu"
LEGACY_FENLIU_DATA_DIR="/etc/fenliu"

# GitHub release 镜像前缀（ghproxy 形式：<前缀>/<完整URL>）。
# 环境变量 MIHOMO_MIRROR / GEODATA_MIRROR 设了就排在最前面。
#
# 镜像说明（PR-40）：下面三个都是第三方运营的 GitHub 代理，无官方背书、
# 无 SLA、无可审计性——不要把它们当作信任根。它们只是传输加速：下载
# 永远先试直连 github.com（download_file 的第一个候选就是直连），
# 镜像只在直连失败时兜底；不论从哪条路下回来，都必须通过
# scripts/asset-checksums.sha256 里的固定 SHA256 校验才算数，代理返回
# 什么都不能绕过这一步。三个代理中任何一个被攻破/投毒，最多让下载
# 失败，不可能让投毒内容装进系统（校验不通过即中止）。直连可用时
# 建议留空镜像变量只走直连；网络实在走不通再用镜像。
# 校验清单里没有对应哈希的版本（如自行指定旧版 MIHOMO_VERSION）会被
# 直接拒绝安装，见 verify_sha256。
DEFAULT_MIRRORS="https://gh-proxy.com https://mirror.ghproxy.com https://ghfast.top"

# 下载资产 SHA256 校验清单（H-13 信任根；与 Dockerfile 共用同一文件）。
ASSET_CHECKSUMS="$SCRIPT_DIR/scripts/asset-checksums.sha256"

NONINTERACTIVE="${LANMUX_NONINTERACTIVE:-0}"
FRESH_INSTALL="${LANMUX_FRESH_INSTALL:-0}"
# PASSWORDS_FROM_FILE：密码文件里实际读到的密码键（空格分隔），供
# warn_env_passwords 区分“密码来自文件”与“密码来自环境变量”。
PASSWORDS_FROM_FILE=""
# _PARSE_WARNED_FILE：白名单解析器已对哪个文件告警过（同一坏文件只告警一次）。
_PARSE_WARNED_FILE=""
UPGRADE_MODE=0
HAVE_EXISTING_INSTALL=0

# 解析后最终生效的值（环境变量 → 已存设置 → 默认值 → 交互提问）。
# 注意：SS_PASSWORD / MIHOMO_SECRET / ADMIN_PASSWORD / SS_CIPHER 这四个
# 变量名与环境变量同名，初始化时必须用 ${VAR:-} 保留传入值——写成
# VAR="" 会把一键安装命令里的密码悄悄清空（stub-run 实测抓到的 bug）。
LAN_IP=""
SS_PORT=""
SS_CIPHER="${SS_CIPHER:-}"
SS_PASSWORD="${SS_PASSWORD:-}"
MIXED_PORT=""
MIXED_AUTH_USER=""
MIXED_AUTH_PASS=""
CONTROLLER_PORT=""
WEB_PORT=""
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
MIHOMO_SECRET="${MIHOMO_SECRET:-}"
EXTERNAL_UI=""

# 端口占用者信息（check_port 填入，供报错展示）。
PORT_OWNER_PID=""
PORT_OWNER_EXE=""
PORT_OWNER_COMM=""

MISSING_PKGS=""

# ------------------------------------------------------------------ 日志
log_info() { echo "[..] $*"; }
log_ok() { echo "[ OK ] $*"; }
log_warn() { echo "[WARN] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

# ------------------------------------------------------------------ 小工具
# 允许 safe_rm_rf 删除的根（H-14）：LanMux 自己的程序/数据目录及其子路径，
# 以及改名前的旧名目录。其它一切路径一律拒绝——尤其拒绝系统目录本身
# （/、/etc、/usr、/opt、/home、/root、/var 等）与 $HOME。
# 路径覆盖变量（LANMUX_INSTALL_DIR / LANMUX_DATA_DIR）也必须落在这里面，
# 否则 validate_install_paths 在安装开始前就拒绝（残留的测试环境变量
# + sudo -E 不得把安装指向系统目录）。
LANMUX_ALLOWED_RM_ROOTS="/opt/lanmux /etc/lanmux /var/lib/lanmux /opt/lan-proxy-hub /etc/lan-proxy-hub /opt/fenliu /etc/fenliu"

validate_rm_target() {
    # validate_rm_target <path> — 校验删除目标：成功时打印规范化路径并返回 0；
    # 失败时把原因打印到 stderr 并返回 1（不删除任何东西）。只做校验，不删除。
    local target="$1"
    local canon=""
    local root=""
    if [ -z "$target" ]; then
        echo "空路径" >&2
        return 1
    fi
    if [ -L "$target" ]; then
        echo "目标本身是符号链接（$target），拒绝删除" >&2
        return 1
    fi
    case "$target" in
        '..'|'../'*|'*/../'*|'*/..')
            # .. 分量不参与白名单匹配：原始串做前缀匹配时
            # /opt/lanmux/../etc 会被误判为 /opt/lanmux 之下（实为 /opt/etc）。
            echo "目标含 .. 路径穿越（$target），拒绝删除" >&2
            return 1
            ;;
    esac
    if command -v readlink >/dev/null 2>&1; then
        # 规范化：消掉 ..、重复斜杠，并展开路径中任何一级符号链接，
        # 防止“允许根下的链接指向系统目录”绕过白名单。
        # 用 -m 不用 -f：-f 要求路径全存在，不存在时失败回退到原始串，
        # 原始串再做前缀匹配就会放行穿越路径；-m 不要求存在。
        canon="$(readlink -m -- "$target" 2>/dev/null || printf '%s' "$target")"
    else
        canon="$target"
    fi
    while [ "$canon" != "/" ] && [ "${canon%/}" != "$canon" ]; do
        canon="${canon%/}"
    done
    if [ -z "$canon" ] || [ "$canon" = "/" ]; then
        echo "拒绝删除根目录或空路径" >&2
        return 1
    fi
    for root in $LANMUX_ALLOWED_RM_ROOTS; do
        case "$canon" in
            "$root"|"$root"/*)
                printf '%s' "$canon"
                return 0
                ;;
        esac
    done
    echo "目标 $canon 不在允许的 LanMux 删除范围（允许：$LANMUX_ALLOWED_RM_ROOTS 及其子路径）" >&2
    return 1
}

safe_rm_rf() {
    # safe_rm_rf <path> — 带护栏的 rm -rf（H-14）：先过白名单校验，删除前
    # 打印目标（非交互模式也至少打日志），校验失败直接 die，不删任何东西。
    local target="$1"
    local canon=""
    if [ -z "$target" ]; then
        die "内部错误：safe_rm_rf 收到空路径，拒绝执行"
    fi
    if ! canon="$(validate_rm_target "$target")"; then
        die "内部错误：safe_rm_rf 拒绝删除 $target（原因见上方）"
    fi
    log_info "删除目录：$target（解析后：$canon）"
    rm -rf -- "$target"
}

require_lanmux_marker() {
    # require_lanmux_marker <dir> <marker...> — 删除目录前的标记校验（H-14）。
    # 目录不存在或为空时放行；非空目录必须含至少一个 LanMux 标记文件
    # （程序目录：backend/bin/frontend/venv/uninstall.sh；数据目录：
    # lanmux.env/lanmux.db/config.yaml 及旧名 hub.db/hub.env/fenliu.db/
    # fenliu.env），否则拒绝删除并报错——路径一旦配错，宁可拒绝也不误删
    # 他人数据或系统目录。
    local dir="$1"
    local m=""
    if [ "$#" -lt 2 ]; then
        die "内部错误：require_lanmux_marker 未传标记文件"
    fi
    shift
    if [ ! -e "$dir" ]; then
        return 0
    fi
    if [ ! -d "$dir" ]; then
        die "拒绝删除 $dir：不是目录"
    fi
    if [ -z "$(find "$dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
        return 0
    fi
    for m in "$@"; do
        if [ -e "$dir/$m" ]; then
            return 0
        fi
    done
    die "拒绝删除 $dir：目录非空且不含 LanMux 标记文件（应含其中之一：$*），疑似他人数据或路径配错，已中止"
}

backup_data_dir() {
    # backup_data_dir <dir> — 清空前把目录整份 cp -a 到带时间戳的兄弟目录
    # （D-07）。目录不存在时直接返回；备份失败时 die，拒绝继续清空。
    # 备份路径记在 LAST_BACKUP_DIR，供日志与排障使用。
    local src="$1"
    local stamp=""
    local dest=""
    if [ ! -e "$src" ]; then
        return 0
    fi
    stamp="$(date +%Y%m%d-%H%M%S)"
    dest="${src}-backup-${stamp}"
    if [ -e "$dest" ]; then
        dest="${dest}-$$"
    fi
    log_info "清空前自动备份：$src -> $dest"
    cp -a -- "$src" "$dest" || die "自动备份失败（$src -> $dest），已拒绝清空数据"
    if [ ! -d "$dest" ]; then
        die "自动备份失败：备份目录未生成 $dest，已拒绝清空数据"
    fi
    LAST_BACKUP_DIR="$dest"
    log_ok "已有数据已备份到 $dest（全新安装完成后确认无误可手动删除）"
}

check_fresh_install_confirm() {
    # check_fresh_install_confirm — 全新安装的二次确认门（D-07）。
    # LANMUX_FRESH_INSTALL=1 且已有安装时，必须同时设置
    # LANMUX_FRESH_INSTALL_CONFIRM=1，否则拒绝清空并报明原因。
    # 交互模式下同样要求（FRESH_INSTALL=1 会跳过模式提问，本来没有任何确认）。
    if [ "$FRESH_INSTALL" = "1" ] && [ "$HAVE_EXISTING_INSTALL" -eq 1 ]; then
        if [ "${LANMUX_FRESH_INSTALL_CONFIRM:-0}" != "1" ]; then
            die "拒绝清空数据：LANMUX_FRESH_INSTALL=1 要求二次确认（LANMUX_FRESH_INSTALL_CONFIRM=1），否则不会清空已有数据。请确认要丢弃全部数据后，同时设置两个变量再重跑；只想升级请去掉 LANMUX_FRESH_INSTALL（非交互默认升级，交互模式选 [1]）。"
        fi
    fi
}

validate_install_paths() {
    # validate_install_paths — 路径覆盖变量白名单校验（H-14），安装开始前做。
    # INSTALL_DIR/DATA_DIR 必须位于允许的 LanMux 根之下；SYSTEMD_DIR 必须
    # 位于 /etc/systemd/system 之下。残留的测试环境变量 + sudo -E 导致
    # 路径指向系统目录时，在这里就拒绝，而不是等到 rm -rf 时才发现。
    local d=""
    for d in "$INSTALL_DIR" "$DATA_DIR"; do
        if ! validate_rm_target "$d" >/dev/null 2>&1; then
            die "路径覆盖变量非法：$d 不在允许的 LanMux 目录之下（允许 /opt/lanmux、/etc/lanmux、/var/lib/lanmux 及其子路径，旧名 /opt/lan-proxy-hub、/etc/lan-proxy-hub、/opt/fenliu、/etc/fenliu）。请检查 LANMUX_INSTALL_DIR / LANMUX_DATA_DIR 是否残留了测试值。"
        fi
    done
    case "$SYSTEMD_DIR" in
        /etc/systemd/system|/etc/systemd/system/*)
            ;;
        *)
            die "路径覆盖变量非法：SYSTEMD_DIR=$SYSTEMD_DIR 必须为 /etc/systemd/system 或其子路径（LANMUX_SYSTEMD_DIR）。"
            ;;
    esac
}

mask_secret() {
    # mask_secret <value> — 只露首尾各 2 位：ab****yz。
    local value="$1"
    local len="${#value}"
    if [ "$len" -le 4 ]; then
        printf '****'
        return 0
    fi
    printf '%s****%s' "${value:0:2}" "${value: -2}"
}

random_hex() {
    # random_hex <bytes> — 密码学随机 hex（mihomo secret 用）。
    local nbytes="$1"
    "${PYBIN:-python3}" -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "$nbytes"
}

random_password() {
    # random_password <len> — 字母数字随机密码（SS 密码自动生成用）。
    local len="$1"
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len"
    echo ""
}

env_quote() {
    # env_quote <value> — 输出双引号包裹的 lanmux.env 值，转义 \ " $ `。
    # systemd EnvironmentFile 与 bash source 都能正确解析这种形式。
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\\$}"
    value="${value//\`/\\\`}"
    printf '"%s"' "$value"
}

db_setting() {
    # db_setting <key> — 打印已存 settings 值（无则打印空行）。
    # 只用 Python 标准库 sqlite3，不依赖 venv（提问阶段 venv 还不存在）。
    # 注意：DB 是事实源——网页改过的端口只在 DB 里，lanmux.env 会过期。
    local key="$1"
    if [ ! -f "$DB_PATH" ]; then
        return 0
    fi
    "${PYBIN:-python3}" -c 'import sqlite3,sys
con = sqlite3.connect(sys.argv[1])
row = con.execute("SELECT value FROM settings WHERE key=?", (sys.argv[2],)).fetchone()
print(row[0] if row else "")' "$DB_PATH" "$key" 2>/dev/null || true
}

_env_inner_is_clean() {
    # _env_inner_is_clean <inner> — 检查双引号值内部有无未转义的 $、反引号或
    # 双引号：都没有返回 0；有则返回 1。反斜杠转义下一字符（env_quote 只
    # 生成 \\ \" \$ \` 四种转义）。只做检查，不执行任何内容。
    local s="$1"
    local i=0
    local c=""
    while [ "$i" -lt "${#s}" ]; do
        c="${s:$i:1}"
        if [ "$c" = '\' ]; then
            i=$((i + 2))
            continue
        fi
        case "$c" in
            '$'|'`'|'"')
                return 1
                ;;
        esac
        i=$((i + 1))
    done
    return 0
}

_env_unescape_dquote() {
    # _env_unescape_dquote <inner> — 还原双引号值内的 env_quote 转义
    # （\\ \" \$ \`）。其它反斜杠原样保留。只做字符串处理，不执行。
    local s="$1"
    local out=""
    local i=0
    local c=""
    local n=""
    while [ "$i" -lt "${#s}" ]; do
        c="${s:$i:1}"
        if [ "$c" = '\' ] && [ "$((i + 1))" -lt "${#s}" ]; then
            n="${s:$((i + 1)):1}"
            case "$n" in
                '\'|'"'|'$'|'`')
                    out+="$n"
                    i=$((i + 2))
                    continue
                    ;;
            esac
        fi
        out+="$c"
        i=$((i + 1))
    done
    printf '%s' "$out"
}

parse_env_file_value() {
    # parse_env_file_value <file> <key> — 白名单解析 env 文件（L-25），
    # 替代 source：绝不执行文件内容。只认 KEY=VALUE 行（KEY 为
    # [A-Z_][A-Z0-9_]*，行首可带一个 export）；值支持双引号（env_quote
    # 写法，转义逐一还原）、单引号（字面）与不含 shell 元字符的裸值。
    # 任一行不符合形状、或含未转义的 $(、反引号、$，或引号未闭合，
    # 整个文件拒绝解析（打印空并告警一次，调用方回落到 DB/空值）。
    # 注意：密码里含 $( 或反引号时无法用此文件传入，请走交互输入。
    local file="$1"
    local key="$2"
    local line=""
    local k=""
    local rest=""
    local first=""
    local last=""
    local inner=""
    local val=""
    local found=""
    local bad=""
    local j=0
    local t=0
    if [ ! -f "$file" ]; then
        return 0
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        while true; do
            case "$line" in
                ' '*) line="${line# }" ;;
                $'\t'*) line="${line#?}" ;;
                *) break ;;
            esac
        done
        while true; do
            case "$line" in
                *' ') line="${line% }" ;;
                *$'\t') line="${line%?}" ;;
                *) break ;;
            esac
        done
        case "$line" in
            ''|'#'*)
                continue
                ;;
        esac
        case "$line" in
            export\ *)
                line="${line#export }"
                ;;
        esac
        case "$line" in
            *=*)
                k="${line%%=*}"
                rest="${line#*=}"
                ;;
            *)
                bad="含无法解析的行（不是 KEY=VALUE 形式）"
                break
                ;;
        esac
        if ! [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
            bad="含非法键名：$k"
            break
        fi
        if [ -z "$rest" ]; then
            val=""
        else
            first="${rest:0:1}"
            last="${rest: -1}"
            if [ "$first" = '"' ]; then
                if [ "$last" != '"' ] || [ "${#rest}" -lt 2 ]; then
                    bad="双引号值未闭合"
                    break
                fi
                inner="${rest:1}"
                inner="${inner%?}"
                j="${#inner}"
                t=0
                while [ "$t" -lt "$j" ] && [ "${inner:$((j - t - 1)):1}" = '\' ]; do
                    t=$((t + 1))
                done
                if [ "$((t % 2))" -eq 1 ]; then
                    bad="双引号值未闭合（收尾引号被转义）"
                    break
                fi
                if ! _env_inner_is_clean "$inner"; then
                    bad="双引号值含未转义的 \$、反引号或双引号"
                    break
                fi
                val="$(_env_unescape_dquote "$inner")"
            elif [ "$first" = "'" ]; then
                if [ "$last" != "'" ] || [ "${#rest}" -lt 2 ]; then
                    bad="单引号值未闭合"
                    break
                fi
                inner="${rest:1}"
                inner="${inner%?}"
                case "$inner" in
                    *"'"*|*'$('*|*'`'*)
                        bad="单引号值含引号、\$( 或反引号"
                        break
                        ;;
                esac
                val="$inner"
            else
                if ! [[ "$rest" =~ ^[A-Za-z0-9_@%+,:/=.-]+$ ]]; then
                    bad="裸值含 shell 元字符或空白，请用引号包裹"
                    break
                fi
                val="$rest"
            fi
        fi
        if [ "$k" = "$key" ]; then
            found="$val"
        fi
    done < "$file"
    if [ -n "$bad" ]; then
        if [ "$_PARSE_WARNED_FILE" != "$file" ]; then
            log_warn "env 文件已拒绝解析（$bad）：$file（未执行其中任何内容）" >&2
            _PARSE_WARNED_FILE="$file"
        fi
        return 0
    fi
    printf '%s' "$found"
    return 0
}

lanmux_env_number() {
    # lanmux_env_number <key> — 从 lanmux.env 读一个纯数字取值（面板端口用）。
    # 面板端口是部署参数、不进 DB，lanmux.env 是它唯一的记录。
    # 经白名单解析器读（L-25），再校验纯数字；文件不存在/解析失败/非数字
    # 时打印空行（调用方回落到默认值）。
    local key="$1"
    local raw=""
    raw="$(parse_env_file_value "$LANMUX_ENV" "$key")"
    case "$raw" in
        ''|*[!0-9]*)
            return 0
            ;;
        *)
            printf '%s' "$raw"
            ;;
    esac
}

lanmux_env_value() {
    # lanmux_env_value <key> — 从现有 lanmux.env 读一个密码类取值（升级时继承用）。
    # 只认 ADMIN_PASSWORD / MIHOMO_SECRET / SS_PASSWORD 三个键。
    # 经白名单解析器读（L-25），绝不 source 文件；文件不存在或解析失败
    # 时打印空行（调用方再回落到 DB）。
    local key="$1"
    case "$key" in
        ADMIN_PASSWORD|MIHOMO_SECRET|SS_PASSWORD)
            ;;
        *)
            return 0
            ;;
    esac
    parse_env_file_value "$LANMUX_ENV" "$key"
}

detect_lan_ip() {
    local ip=""
    if command -v ip >/dev/null 2>&1; then
        ip="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    fi
    if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    printf '%s' "${ip:-127.0.0.1}"
}

valid_port() {
    # valid_port <value> — 1-65535 的纯数字。
    local value="$1"
    case "$value" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$value" -ge 1 ] && [ "$value" -le 65535 ]; then
        return 0
    fi
    return 1
}

valid_cipher() {
    local value="$1"
    case "$value" in
        aes-128-gcm|aes-256-gcm|chacha20-ietf-poly1305|2022-blake3-aes-128-gcm|2022-blake3-aes-256-gcm)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ------------------------------------------------------------------ 提问
# 每个 read 都显式处理 EOF（set -e 下 read 遇 EOF 返回非零会直接退出）。
ask() {
    # ask <变量名> <提示> <默认值> [标签] — 空输入保留默认值。
    local varname="$1"
    local prompt="$2"
    local default="$3"
    local tag="${4:-}"
    local answer=""
    printf '%s' "$prompt"
    if [ -n "$tag" ]; then
        printf ' %s' "$tag"
    fi
    if [ -n "$default" ]; then
        printf ' [回车默认：%s]' "$default"
    fi
    printf ': '
    if ! read -r answer; then
        echo ""
        die "输入中断，安装已取消（未做任何修改）。"
    fi
    if [ -z "$answer" ]; then
        answer="$default"
    fi
    printf -v "$varname" '%s' "$answer"
}

ask_secret() {
    # ask_secret <变量名> <提示> <默认说明> — 不回显，默认值不打印明文。
    # 空输入返回空字符串（调用方决定是“随机生成”还是“保持现有”）。
    local varname="$1"
    local prompt="$2"
    local default_hint="$3"
    local answer=""
    printf '%s' "$prompt"
    if [ -n "$default_hint" ]; then
        printf ' [%s]' "$default_hint"
    fi
    printf ': '
    if ! read -r -s answer; then
        echo ""
        die "输入中断，安装已取消（未做任何修改）。"
    fi
    echo ""
    printf -v "$varname" '%s' "$answer"
}

ask_port() {
    # ask_port <变量名> <提示> <默认值> — 校验数字范围与端口互斥，错了当场重问。
    local varname="$1"
    local prompt="$2"
    local default="$3"
    local value=""
    while true; do
        ask value "$prompt" "$default"
        if ! valid_port "$value"; then
            echo "  端口必须是 1-65535 的数字，请重新输入。"
            continue
        fi
        if [ "$value" = "$SS_PORT" ] || [ "$value" = "$MIXED_PORT" ] \
            || [ "$value" = "$CONTROLLER_PORT" ] || [ "$value" = "$WEB_PORT" ]; then
            echo "  端口 $value 已被 LanMux 的另一个入口占用，请换一个。"
            continue
        fi
        break
    done
    printf -v "$varname" '%s' "$value"
}

# ------------------------------------------------------------------ 下载
# 所有网络拉取都走 download_file：直连 + 镜像兜底、超时、重试、
# 落盘后按最小体积校验；全部失败时一条可操作的错误退出。
download_file() {
    # download_file <url> <dest> <min_bytes> <label> <max_time> [镜像前缀...]
    local url="$1"
    local dest="$2"
    local min_bytes="$3"
    local label="$4"
    local max_time="$5"
    shift 5
    local prefix=""
    local candidate=""
    local size=0
    local tried=""
    for prefix in "" "$@"; do
        if [ -z "$prefix" ]; then
            candidate="$url"
        else
            candidate="${prefix}/${url}"
        fi
        tried="${tried} ${candidate}"
        log_info "下载 ${label}：${candidate}"
        if curl -fsSL --connect-timeout 10 --max-time "$max_time" --retry 1 \
            -o "${dest}.tmp" "$candidate" 2>/dev/null; then
            size="$(stat -c %s "${dest}.tmp" 2>/dev/null || echo 0)"
            if [ "$size" -ge "$min_bytes" ]; then
                mv "${dest}.tmp" "$dest"
                log_ok "${label} 下载完成（${size} 字节）"
                return 0
            fi
            log_warn "${label} 体积异常（${size} 字节，小于 ${min_bytes}），换源重试"
        else
            log_warn "${label} 下载失败，换源重试"
        fi
        rm -f "${dest}.tmp"
    done
    rm -f "${dest}.tmp"
    die "下载 ${label} 失败，已尝试：${tried}。请检查网络，或用 MIHOMO_MIRROR / GEODATA_MIRROR 指定镜像前缀后重跑。"
}

mirror_list_for() {
    # mirror_list_for <env_override> — 打印镜像前缀列表（覆盖值排最前）。
    local override="$1"
    if [ -n "$override" ]; then
        printf '%s %s' "$override" "$DEFAULT_MIRRORS"
    else
        printf '%s' "$DEFAULT_MIRRORS"
    fi
}

download_with_mirrors() {
    # download_with_mirrors <url> <dest> <min_bytes> <label> <max_time> <覆盖值>
    # download_file 的薄封装：把镜像列表读进数组再传，避免无引用的命令替换。
    local url="$1"
    local dest="$2"
    local min_bytes="$3"
    local label="$4"
    local max_time="$5"
    local override="$6"
    local mirrors=()
    read -ra mirrors <<< "$(mirror_list_for "$override")"
    download_file "$url" "$dest" "$min_bytes" "$label" "$max_time" "${mirrors[@]}"
}

lookup_sha256() {
    # lookup_sha256 <清单里的文件名> — 打印对应的 64 位 hex 哈希。
    # 清单缺失、或文件名无对应行、或哈希格式不对时直接 die（fail-closed：
    # 没有可信哈希就拒绝安装，绝不跳过校验）。
    local name="$1"
    local line=""
    local hash=""
    if [ ! -f "$ASSET_CHECKSUMS" ]; then
        die "校验清单缺失：$ASSET_CHECKSUMS 不存在，无法校验下载，安装中止（请确认仓库完整克隆）。"
    fi
    line="$(awk -v name="$name" '$1 !~ /^#/ && NF == 2 && $2 == name {print}' "$ASSET_CHECKSUMS" 2>/dev/null || true)"
    if [ -z "$line" ]; then
        die "校验清单中没有 ${name} 的 SHA256 记录（可能指定了未钉哈希的版本），拒绝安装。请用默认版本重跑，或等维护者把该版本哈希钉进 scripts/asset-checksums.sha256。"
    fi
    if [ "$(printf '%s\n' "$line" | wc -l)" -ne 1 ]; then
        die "校验清单中 ${name} 有多条记录，清单已损坏，安装中止。"
    fi
    hash="${line%%  *}"
    case "$hash" in
        *[!0-9a-f]*|'')
            die "校验清单中 ${name} 的哈希格式非法：${hash}，安装中止。"
            ;;
    esac
    if [ "${#hash}" -ne 64 ]; then
        die "校验清单中 ${name} 的哈希不是 64 位 hex（长 ${#hash}），安装中止。"
    fi
    printf '%s' "$hash"
}

verify_sha256() {
    # verify_sha256 <文件路径> <清单里的文件名> <说明>
    # 按清单哈希强制校验；不匹配时删掉该文件并 die（安装中止）。
    local file="$1"
    local name="$2"
    local label="$3"
    local expected=""
    local actual=""
    local dir=""
    local base=""
    expected="$(lookup_sha256 "$name")"
    if [ ! -f "$file" ]; then
        die "${label} 校验失败：文件不存在：$file"
    fi
    dir="$(dirname -- "$file")"
    base="$(basename -- "$file")"
    actual="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
    if ! (cd "$dir" && printf '%s  %s\n' "$expected" "$base" | sha256sum -c - >/dev/null 2>&1); then
        rm -f "$file"
        die "${label} SHA256 校验失败，安装中止。期望 ${expected}，实际 ${actual}。已删除可疑文件：$file（可能下载被篡改、镜像投毒或上游更新了内容；请检查网络与镜像，或等维护者更新 scripts/asset-checksums.sha256 后重跑）。"
    fi
    log_ok "${label} SHA256 校验通过"
}

verify_existing_sha256() {
    # verify_existing_sha256 <文件路径> <清单里的文件名> <说明>
    # 供 install_geodata 复用已存在文件时调用：校验通过返回 0；
    # 不匹配返回 1（调用方删了重下），清单缺失/损坏时照样 die。
    local file="$1"
    local name="$2"
    local label="$3"
    local expected=""
    local actual=""
    local dir=""
    local base=""
    expected="$(lookup_sha256 "$name")"
    dir="$(dirname -- "$file")"
    base="$(basename -- "$file")"
    actual="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
    if (cd "$dir" && printf '%s  %s\n' "$expected" "$base" | sha256sum -c - >/dev/null 2>&1); then
        log_ok "${label} 已存在且 SHA256 校验通过，跳过下载"
        return 0
    fi
    log_warn "${label} 已存在但 SHA256 不匹配（期望 ${expected}，实际 ${actual}），疑似损坏或被篡改，重新下载"
    return 1
}

# ------------------------------------------------------------------ 预检
# select_python — 选一个 >= 3.11 的 Python 解释器，记入全局 PYBIN。
# 优先系统 python3；不够新时找版本化二进制（Ubuntu 22.04 自带 3.10，
# 但 deadsnakes 的 python3.11 可用；Debian 11 同理）。一个都找不到才报错。
# 注意：不要用 update-alternatives 把系统 python3 指向新版本——那会破坏
# apt 等系统工具；用版本化二进制才是正路。
PYBIN=""
select_python() {
    local cand=""
    for cand in python3 python3.12 python3.11 python3.13; do
        if command -v "$cand" >/dev/null 2>&1 \
            && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
            PYBIN="$cand"
            local pyver=""
            pyver="$("$PYBIN" --version 2>&1)"
            log_ok "Python：$PYBIN（$pyver）"
            return 0
        fi
    done
    local cur=""
    cur="$(python3 --version 2>&1 || echo 未安装)"
    die "未找到 Python 3.11+（当前 python3 是 $cur）。Ubuntu 22.04 可执行：sudo add-apt-repository -y ppa:deadsnakes/ppa && sudo apt-get install -y python3.11 python3.11-venv，然后重跑安装。"
}

check_env_file_perms() {
    # check_env_file_perms <file> — 密码文件必须是 600 或 400（仅属主可读写），
    # 组/其他任何权限都拒绝（L-26）。拿不到权限位时同样拒绝。
    local file="$1"
    local mode=""
    mode="$(stat -c %a -- "$file" 2>/dev/null || echo "")"
    case "$mode" in
        600|400)
            return 0
            ;;
        *)
            die "安装密码文件权限过宽或无法读取：$file 当前权限 ${mode:-未知}，必须是 600（仅属主可读写）。请执行：chmod 600 $file"
            ;;
    esac
}

load_install_env_file() {
    # load_install_env_file — 从 LANMUX_INSTALL_ENV_FILE 密码文件读三个密码
    # （L-26），替代命令行传密码。文件未设置时直接返回（交互安装与环境
    # 变量路径不受影响）；文件不存在、权限过宽或内容含命令替换时拒绝安装。
    # 密码文件优先于环境变量：环境变量里同时有同名密码时，文件值覆盖它并告警。
    local file="${LANMUX_INSTALL_ENV_FILE:-}"
    local k=""
    local v=""
    local old=""
    if [ -z "$file" ]; then
        return 0
    fi
    if [ ! -f "$file" ]; then
        die "安装密码文件不存在：$file（LANMUX_INSTALL_ENV_FILE）"
    fi
    check_env_file_perms "$file"
    for k in ADMIN_PASSWORD SS_PASSWORD MIHOMO_SECRET; do
        v="$(parse_env_file_value "$file" "$k")"
        if [ -z "$v" ]; then
            continue
        fi
        case "$k" in
            ADMIN_PASSWORD) old="$ADMIN_PASSWORD" ;;
            SS_PASSWORD) old="$SS_PASSWORD" ;;
            MIHOMO_SECRET) old="$MIHOMO_SECRET" ;;
        esac
        if [ -n "$old" ] && [ "$old" != "$v" ]; then
            log_warn "环境变量中的 $k 已被密码文件 $file 覆盖（命令行传密码不安全，请勿再用）。"
        fi
        printf -v "$k" '%s' "$v"
        PASSWORDS_FROM_FILE="$PASSWORDS_FROM_FILE $k"
        log_info "已从密码文件读取 $k（$file）"
    done
}

warn_env_passwords() {
    # warn_env_passwords — 密码经环境变量传入时告警一次（L-26）：命令行赋值
    # 会写入 shell history，进程存活期间同用户经 /proc/<pid>/environ 可见。
    # 已从密码文件读取的项不告警。
    local k=""
    local v=""
    local names=""
    for k in ADMIN_PASSWORD SS_PASSWORD MIHOMO_SECRET; do
        case " $PASSWORDS_FROM_FILE " in
            *" $k "*)
                continue
                ;;
        esac
        case "$k" in
            ADMIN_PASSWORD) v="$ADMIN_PASSWORD" ;;
            SS_PASSWORD) v="$SS_PASSWORD" ;;
            MIHOMO_SECRET) v="$MIHOMO_SECRET" ;;
        esac
        if [ -n "$v" ]; then
            names="$names $k"
        fi
    done
    if [ -n "$names" ]; then
        log_warn "密码$names 经环境变量传入（命令行赋值会写入 shell history，进程存活期间经 /proc/<pid>/environ 可见）。建议改用密码文件：先 chmod 600 写好含密码的文件，再用 LANMUX_INSTALL_ENV_FILE=<文件> 重跑；或直接交互安装（sudo bash install.sh）。"
    fi
}

preflight_env() {
    log_info "预检：运行环境"
    if [ "$(id -u)" -ne 0 ]; then
        die "请用 root 或 sudo 运行安装器（需要写 /opt、/etc 与 systemd 单元）。"
    fi
    # 路径覆盖白名单 + 密码文件加载（H-14/L-26）：在任何删除/写盘之前做。
    validate_install_paths
    load_install_env_file
    warn_env_passwords
    if [ ! -d "$SCRIPT_DIR/backend/app" ] || [ ! -f "$SCRIPT_DIR/frontend/index.html" ]; then
        die "找不到后端/前端源码。请在仓库根目录运行：cd lanmux && sudo bash install.sh"
    fi
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            debian|ubuntu|raspbian)
                log_ok "系统：${PRETTY_NAME:-$ID}"
                ;;
            *)
                if [ "${LANMUX_SKIP_OS_CHECK:-0}" != "1" ]; then
                    die "不支持的系统 ${ID:-未知}：本安装器面向 Debian/Ubuntu（含 Armbian）。确认要继续请加 LANMUX_SKIP_OS_CHECK=1 重跑。"
                fi
                log_warn "跳过系统检查（LANMUX_SKIP_OS_CHECK=1）：${ID:-未知}"
                ;;
        esac
    else
        log_warn "无 /etc/os-release，跳过系统检查"
    fi
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)
            die "不支持的架构 $(uname -m)：仅支持 amd64（x86_64）与 arm64（aarch64）。"
            ;;
    esac
    log_ok "架构：$(uname -m) → ${ARCH}"
    select_python
    # 注意：只测 import venv 不够——Armbian 上 venv 能 import 但
    # ensurepip 缺失，python3 -m venv 会报 ensurepip is not available。
    # 两者都测，缺其一就装对应版本的 -venv 包。
    if ! "$PYBIN" -c 'import venv, ensurepip' 2>/dev/null; then
        MISSING_PKGS="$MISSING_PKGS ${PYBIN}-venv"
    fi
    # 系统 pip 只在 PYBIN=python3 时检查：版本化二进制（如 python3.11）
    # 没有对应的 -pip 包，venv 里的 pip 由 ensurepip 提供，不需要系统 pip。
    if [ "$PYBIN" = "python3" ] && ! python3 -m pip --version >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS python3-pip"
    fi
    if ! command -v curl >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS curl"
    fi
    if [ ! -f /etc/ssl/certs/ca-certificates.crt ]; then
        MISSING_PKGS="$MISSING_PKGS ca-certificates"
    fi
    if ! command -v gzip >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS gzip"
    fi
    if ! command -v tar >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS tar"
    fi
    if ! command -v ss >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS iproute2"
    fi
    MISSING_PKGS="$(echo "$MISSING_PKGS" | sed 's/^ *//')"
    if [ -n "$MISSING_PKGS" ]; then
        log_info "待安装系统依赖：$MISSING_PKGS（确认页会再展示，装失败会给手动命令）"
    fi
    # 磁盘：mihomo 解压约 60MB + venv 约 80MB + geodata 约 30MB + 面板约 10MB。
    local free_kb=""
    free_kb="$(df -k /opt 2>/dev/null | awk 'NR==2 {print $4}')"
    if [ -n "$free_kb" ] && [ "$free_kb" -lt 512000 ]; then
        die "磁盘空间不足：/opt 可用 $((free_kb / 1024))MB，需至少 500MB。"
    fi
    log_ok "环境预检通过"
}

port_pid() {
    # port_pid <port> — 打印监听该 TCP 端口的 PID（查不到则空）。
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -E ":${port} " | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1
        return 0
    fi
    if command -v fuser >/dev/null 2>&1; then
        fuser "${port}/tcp" 2>/dev/null | awk '{print $1}'
        return 0
    fi
    return 0
}

check_port() {
    # check_port <port> — 返回 0 空闲 / 1 被本 LanMux 自己的服务占用（升级可接受）
    # / 2 被其他进程占用（此时 PORT_OWNER_* 填入占用者信息）。
    local port="$1"
    local pid=""
    local exe=""
    local comm=""
    local cmdline=""
    PORT_OWNER_PID=""
    PORT_OWNER_EXE=""
    PORT_OWNER_COMM=""
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        return 0
    fi
    pid="$(port_pid "$port")"
    if [ -n "$pid" ] && [ -e "/proc/$pid/exe" ]; then
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
        comm="$(cat "/proc/$pid/comm" 2>/dev/null || true)"
    fi
    # 是本 LanMux 自己的进程吗？看可执行文件或命令行是否在安装目录下
    # （lanmux-web 是 venv python，/proc exe 指向系统 python，故两项都查）。
    # 旧名安装目录也认（v0.9.0 改名前跑的是旧路径，迁移在预检之后才做）。
    case "$exe" in
        "$INSTALL_DIR"/*|"$LEGACY_INSTALL_DIR"/*)
            return 1
            ;;
    esac
    if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then
        cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
        case "$cmdline" in
            *"$INSTALL_DIR"*|*"$LEGACY_INSTALL_DIR"*)
                return 1
                ;;
        esac
    fi
    PORT_OWNER_PID="$pid"
    PORT_OWNER_EXE="$exe"
    PORT_OWNER_COMM="$comm"
    return 2
}

port_preflight() {
    # port_preflight — 检查四个端口；冲突时打印占用者与两种解法，返回 1。
    log_info "预检：端口（SS ${SS_PORT} / Mixed ${MIXED_PORT} / 控制器 ${CONTROLLER_PORT} / 面板 ${WEB_PORT}）"
    local conflict=0
    local spec=""
    local port=""
    local label=""
    local envvar=""
    local rc=0
    for spec in "${SS_PORT}:SS 入口:LANMUX_SS_PORT" "${MIXED_PORT}:Mixed 入口:LANMUX_MIXED_PORT" "${CONTROLLER_PORT}:Mihomo 控制器:LANMUX_CONTROLLER_PORT" "${WEB_PORT}:管理面板:LANMUX_WEB_PORT"; do
        port="${spec%%:*}"
        label="${spec#*:}"
        label="${label%%:*}"
        envvar="${spec##*:}"
        rc=0
        check_port "$port" || rc=$?
        if [ "$rc" -eq 0 ]; then
            log_ok "端口 ${port}（${label}）空闲"
        elif [ "$rc" -eq 1 ]; then
            log_ok "端口 ${port}（${label}）正由 LanMux 服务占用，升级时会重启接管"
        else
            conflict=1
            echo "[ERROR] 端口 ${port}（${label}）已被占用。" >&2
            if [ -n "$PORT_OWNER_PID" ]; then
                echo "        占用进程：${PORT_OWNER_COMM:-未知}（PID ${PORT_OWNER_PID}，${PORT_OWNER_EXE:-未知路径}）" >&2
            else
                echo "        占用进程查不到（未装 iproute2 时无法识别，可先装：apt install iproute2）" >&2
            fi
            if [ "$PORT_OWNER_COMM" = "mihomo" ]; then
                echo "        疑似旧 mihomo-gateway 仍在跑，N1 上二选一：" >&2
                echo "          1) 先停用旧网关：systemctl stop mihomo && systemctl disable mihomo，然后重跑安装；" >&2
                echo "          2) 换端口安装：${envvar}=<空闲端口> sudo -E bash install.sh" >&2
            else
                echo "        解法：停用该进程，或换端口安装：${envvar}=<空闲端口> sudo -E bash install.sh" >&2
            fi
        fi
    done
    if [ "$conflict" -ne 0 ]; then
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------ 取值
resolve_defaults() {
    # 先算每项的默认值（环境变量 → 已存设置 → 默认值），供提问或非交互使用。
    local stored=""
    stored="$(db_setting "lan_ip")"
    LAN_IP="${LANMUX_LAN_IP:-${stored:-$(detect_lan_ip)}}"
    stored="$(db_setting "ss_port")"
    SS_PORT="${LANMUX_SS_PORT:-${stored:-10001}}"
    stored="$(db_setting "ss_cipher")"
    SS_CIPHER="${SS_CIPHER:-${stored:-aes-128-gcm}}"
    stored="$(db_setting "mixed_port")"
    MIXED_PORT="${LANMUX_MIXED_PORT:-${stored:-7890}}"
    stored="$(db_setting "mixed_auth_user")"
    MIXED_AUTH_USER="${LANMUX_MIXED_AUTH_USER:-${stored:-}}"
    stored="$(db_setting "mixed_auth_pass")"
    MIXED_AUTH_PASS="${LANMUX_MIXED_AUTH_PASS:-${stored:-}}"
    stored="$(db_setting "controller_port")"
    CONTROLLER_PORT="${LANMUX_CONTROLLER_PORT:-${stored:-9090}}"
    # 面板端口不进 DB：环境变量 → 上次安装的 lanmux.env → 8086。
    stored="$(lanmux_env_number "LANMUX_WEB_PORT")"
    WEB_PORT="${LANMUX_WEB_PORT:-${stored:-8086}}"
    stored="$(db_setting "external_ui")"
    if [ -n "${LANMUX_EXTERNAL_UI:-}" ]; then
        EXTERNAL_UI="$LANMUX_EXTERNAL_UI"
    elif [ -n "$stored" ]; then
        EXTERNAL_UI="$stored"
    else
        EXTERNAL_UI="$UI_DIR"
    fi
    if [ "$EXTERNAL_UI" = "none" ]; then
        EXTERNAL_UI=""
    fi
    # metacubexd 目录安装时会清空重装：不在允许删除范围内的路径直接拒绝，
    # 别等下载完才在 safe_rm_rf 里失败（H-14）。
    if [ -n "$EXTERNAL_UI" ] && ! validate_rm_target "$EXTERNAL_UI" >/dev/null 2>&1; then
        die "Metacubexd 目录非法：$EXTERNAL_UI 不在允许的 LanMux 删除范围（安装器会清空该目录重装 metacubexd）。请把它放在 /etc/lanmux 或 /opt/lanmux 之下，或设为 none 禁用（LANMUX_EXTERNAL_UI=none）。"
    fi
    # 密码类只在全新安装时生效（升级永不改密码，改密码走网页设置）。
    if [ "$UPGRADE_MODE" -eq 0 ]; then
        SS_PASSWORD="${SS_PASSWORD:-}"
        MIHOMO_SECRET="${MIHOMO_SECRET:-}"
        ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
    else
        if [ -n "${SS_PASSWORD:-}" ] || [ -n "${MIHOMO_SECRET:-}" ] || [ -n "${ADMIN_PASSWORD:-}" ]; then
            log_warn "升级模式忽略环境变量里的密码（SS_PASSWORD / MIHOMO_SECRET / ADMIN_PASSWORD）：升级不改密码，改密码请登录面板后在设置里改。"
        fi
        # 升级：密码绝不写空（v0.4.3 的教训：只读 DB，DB 一时读不到
        # 就把 lanmux.env 里的三个密码全写空了；管理员密码明文只在
        # lanmux.env 有（DB 里只有哈希），写空就再也找不回来）。
        # SS / Mihomo：DB 为准（面板里改过的密码只在 DB 里），DB 读不到
        # 时回落到现有 lanmux.env（v0.4.3 已写空的机器也靠这一层修复）。
        # 管理员密码：只能从现有 lanmux.env 继承；lanmux.env 也没有时留空
        # （诚实的空，不编造；丢了只能在机器上删 admin_password_hash
        # 行后重走向导）。init_lanmux 对密码是只播种不覆盖，传回相同值
        # 也不会改动 DB。
        SS_PASSWORD="$(db_setting "ss_password")"
        if [ -z "$SS_PASSWORD" ]; then
            SS_PASSWORD="$(lanmux_env_value "SS_PASSWORD")"
        fi
        MIHOMO_SECRET="$(db_setting "mihomo_secret")"
        if [ -z "$MIHOMO_SECRET" ]; then
            MIHOMO_SECRET="$(lanmux_env_value "MIHOMO_SECRET")"
        fi
        ADMIN_PASSWORD="$(lanmux_env_value "ADMIN_PASSWORD")"
    fi
}

validate_resolved() {
    # 校验解析出的全部取值（非交互模式靠它拦截非法输入）。
    if ! valid_port "$SS_PORT"; then
        die "SS 端口非法：${SS_PORT}（需 1-65535 的数字）。"
    fi
    if ! valid_port "$MIXED_PORT"; then
        die "Mixed 端口非法：${MIXED_PORT}（需 1-65535 的数字）。"
    fi
    if ! valid_port "$CONTROLLER_PORT"; then
        die "控制器端口非法：${CONTROLLER_PORT}（需 1-65535 的数字）。"
    fi
    if ! valid_port "$WEB_PORT"; then
        die "面板端口非法：${WEB_PORT}（需 1-65535 的数字）。"
    fi
    if [ "$SS_PORT" = "$MIXED_PORT" ] || [ "$SS_PORT" = "$CONTROLLER_PORT" ] \
        || [ "$SS_PORT" = "$WEB_PORT" ] || [ "$MIXED_PORT" = "$CONTROLLER_PORT" ] \
        || [ "$MIXED_PORT" = "$WEB_PORT" ] || [ "$CONTROLLER_PORT" = "$WEB_PORT" ]; then
        die "四个端口必须互不相同：SS=${SS_PORT} Mixed=${MIXED_PORT} 控制器=${CONTROLLER_PORT} 面板=${WEB_PORT}。"
    fi
    if ! valid_cipher "$SS_CIPHER"; then
        die "SS 加密方式非法：${SS_CIPHER}（可选 aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 / 2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm）。"
    fi
    if [ -n "$ADMIN_PASSWORD" ] && [ "${#ADMIN_PASSWORD}" -lt 8 ]; then
        die "管理员密码至少 8 位。"
    fi
    if [ -n "$SS_PASSWORD" ] && [ "${#SS_PASSWORD}" -lt 8 ]; then
        die "SS 密码至少 8 位。"
    fi
}

questionnaire_network() {
    # 网络类取值：IP、四个端口、加密方式、Mixed 鉴权。
    # 端口互斥校验需要逐项清零后再问，避免与自身默认值撞上。
    echo ""
    echo "—— 安装参数（回车接受默认值）——"
    ask LAN_IP "宿主机局域网 IP（用于生成客户端连接信息）" "$LAN_IP"
    local old_ss="$SS_PORT"
    local old_mixed="$MIXED_PORT"
    local old_ctrl="$CONTROLLER_PORT"
    local old_web="$WEB_PORT"
    SS_PORT=""
    MIXED_PORT=""
    CONTROLLER_PORT=""
    WEB_PORT=""
    ask_port SS_PORT "SS 入口端口" "$old_ss"
    ask_port MIXED_PORT "Mixed 入口端口（HTTP/SOCKS5）" "$old_mixed"
    ask_port CONTROLLER_PORT "Mihomo 控制器端口" "$old_ctrl"
    ask_port WEB_PORT "管理面板端口" "$old_web"
    while true; do
        ask SS_CIPHER "SS 加密方式" "$SS_CIPHER"
        if valid_cipher "$SS_CIPHER"; then
            break
        fi
        echo "  加密方式可选：aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 / 2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm"
    done
    ask MIXED_AUTH_USER "Mixed 入口鉴权账号（可跳过，留空=不鉴权）" "$MIXED_AUTH_USER" "[可跳过]"
    if [ -n "$MIXED_AUTH_USER" ]; then
        local tmp_pass=""
        ask_secret tmp_pass "Mixed 入口鉴权密码" "回车默认：保持现有"
        if [ -n "$tmp_pass" ]; then
            MIXED_AUTH_PASS="$tmp_pass"
        fi
    else
        MIXED_AUTH_PASS=""
    fi
}

questionnaire_secrets() {
    # 密码类取值：仅全新安装问（升级永不改密码）。
    # 空输入的语义：首次问时“随机生成”（管理员密码除外，必填）；
    # 重新填写时“保持当前值”。先问到临时变量再决定，避免清空已有值。
    local tmp=""
    while true; do
        if [ -n "$ADMIN_PASSWORD" ]; then
            ask_secret tmp "管理员密码（登录面板用）" "回车默认：保持当前值"
            if [ -z "$tmp" ]; then
                break
            fi
        else
            ask_secret tmp "管理员密码（登录面板用）" "[必填，至少 8 位]"
            if [ -z "$tmp" ]; then
                echo "  管理员密码必填，请重新输入。"
                continue
            fi
        fi
        if [ "${#tmp}" -ge 8 ]; then
            ADMIN_PASSWORD="$tmp"
            break
        fi
        echo "  管理员密码至少 8 位，请重新输入。"
    done
    while true; do
        if [ -n "$SS_PASSWORD" ]; then
            ask_secret tmp "SS 入口密码" "回车默认：保持当前值"
            if [ -z "$tmp" ]; then
                break
            fi
        else
            ask_secret tmp "SS 入口密码" "回车默认：随机生成"
            if [ -z "$tmp" ]; then
                SS_PASSWORD="$(random_password 16)"
                log_info "SS 密码已随机生成（装好后在面板总节点卡片查看/复制）"
                break
            fi
        fi
        if [ "${#tmp}" -ge 8 ]; then
            SS_PASSWORD="$tmp"
            break
        fi
        echo "  SS 密码至少 8 位，请重新输入。"
    done
    ask_secret tmp "Mihomo 控制器 Secret" "回车默认：随机生成"
    if [ -z "$tmp" ]; then
        if [ -z "$MIHOMO_SECRET" ]; then
            MIHOMO_SECRET="$(random_hex 24)"
        fi
    else
        MIHOMO_SECRET="$tmp"
    fi
}

show_confirm() {
    echo ""
    echo "========================================"
    if [ "$UPGRADE_MODE" -eq 1 ]; then
        echo "确认升级 LanMux（保留全部数据）"
    else
        echo "确认安装 LanMux v${LANMUX_VERSION}"
    fi
    echo "========================================"
    echo "安装目录：  $INSTALL_DIR"
    echo "数据目录：  $DATA_DIR"
    echo "局域网 IP： $LAN_IP"
    echo "SS 入口：   ${LAN_IP}:${SS_PORT}（${SS_CIPHER}）"
    echo "Mixed 入口：${LAN_IP}:${MIXED_PORT}$(if [ -n "$MIXED_AUTH_USER" ]; then printf '（鉴权账号 %s）' "$MIXED_AUTH_USER"; fi)"
    echo "控制器：    ${LAN_IP}:${CONTROLLER_PORT}"
    echo "管理面板：  http://${LAN_IP}:${WEB_PORT}/"
    if [ -n "$EXTERNAL_UI" ]; then
        echo "Metacubexd： http://${LAN_IP}:${CONTROLLER_PORT}/ui/（external-ui=${EXTERNAL_UI}）"
    else
        echo "Metacubexd： 不安装（external-ui 未设置，面板里的 Metacubexd 链接打不开）"
    fi
    if [ "$UPGRADE_MODE" -eq 1 ]; then
        echo "管理员密码：保持现有（不改动）"
        echo "SS 密码：   保持现有（不改动）"
        echo "Mihomo Secret：保持现有（不改动）"
    else
        if [ -n "$ADMIN_PASSWORD" ]; then
            echo "管理员密码：$(mask_secret "$ADMIN_PASSWORD")（装好后请在网页设置里改掉默认密码）"
        else
            echo "管理员密码：未设置（首次打开面板时按向导设置）"
        fi
        echo "SS 密码：   $(mask_secret "$SS_PASSWORD")"
        echo "Mihomo Secret：$(mask_secret "$MIHOMO_SECRET")"
    fi
    if [ -n "$MISSING_PKGS" ]; then
        echo "系统依赖：  将自动安装 $MISSING_PKGS"
    else
        echo "系统依赖：  齐全，无需安装"
    fi
    echo "下载内容：  mihomo v${MIHOMO_VERSION}（${ARCH}）+ metacubexd v${METACUBEXD_VERSION} + geodata（GeoIP/GeoSite/Country.mmdb），全部按仓库内固定 SHA256 校验，不匹配即中止"
    echo "启动服务：  lanmux-mihomo.service、lanmux-web.service（开机自启）"
    echo "绝不改动：  /etc/mihomo、mihomo 单元（旧网关）、docker"
    echo "========================================"
}

confirm_loop() {
    local answer=""
    # 密码只在第一轮问；端口冲突重问时只重问网络类（免得反复输密码）。
    # 用户在确认页按 n（重新填写）时，下一轮密码也重问。
    local ask_secrets_now=1
    while true; do
        if [ "$NONINTERACTIVE" -eq 0 ]; then
            questionnaire_network
            if [ "$UPGRADE_MODE" -eq 0 ] && [ "$ask_secrets_now" -eq 1 ]; then
                questionnaire_secrets
            fi
            ask_secrets_now=0
        fi
        validate_resolved
        if ! port_preflight; then
            if [ "$NONINTERACTIVE" -eq 1 ]; then
                die "端口冲突，安装中止（见上方解法）。"
            fi
            echo "端口冲突：请停用占用进程后重跑，或在下面重新填写端口。"
            continue
        fi
        show_confirm
        if [ "$NONINTERACTIVE" -eq 1 ]; then
            log_info "非交互模式：以上述参数继续安装"
            return 0
        fi
        printf '确认安装？[y] 确认  [n] 重新填写  [q] 退出：'
        if ! read -r answer; then
            echo ""
            die "输入中断，安装已取消（未做任何修改）。"
        fi
        case "$answer" in
            y|Y|yes|"")
                return 0
                ;;
            n|N)
                echo "重新填写（默认值即上一次的输入）。"
                ask_secrets_now=1
                continue
                ;;
            q|Q)
                echo "已取消，未做任何修改。"
                exit 0
                ;;
            *)
                echo "请输入 y / n / q。"
                continue
                ;;
        esac
    done
}

# ------------------------------------------------------------------ 安装
install_deps() {
    if [ -z "$MISSING_PKGS" ]; then
        return 0
    fi
    log_info "安装系统依赖：$MISSING_PKGS"
    if ! DEBIAN_FRONTEND=noninteractive apt-get update -qq \
        || ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $MISSING_PKGS; then
        echo "[ERROR] 系统依赖自动安装失败，请手动执行后再重跑：" >&2
        echo "        sudo apt-get update && sudo apt-get install -y $MISSING_PKGS" >&2
        exit 1
    fi
    log_ok "系统依赖安装完成"
}

install_mihomo() {
    log_info "安装 mihomo v${MIHOMO_VERSION}（${ARCH}）"
    local asset="mihomo-linux-${ARCH}-v${MIHOMO_VERSION}.gz"
    local url="https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/${asset}"
    local tmpdir=""
    tmpdir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" EXIT
    # H-13：上游 v1.19.34 不发布 checksums.txt（实测 404），校验不依赖
    # 上游，改用仓库内固定哈希（scripts/asset-checksums.sha256）；不
    # 匹配即中止安装。MIHOMO_VERSION 被改成未钉哈希的版本时，查表失败
    # 同样中止（fail-closed）。
    download_with_mirrors "$url" "${tmpdir}/${asset}" 10000000 "mihomo 二进制" 600 "${MIHOMO_MIRROR:-}"
    verify_sha256 "${tmpdir}/${asset}" "$asset" "mihomo 二进制"
    mkdir -p "$INSTALL_DIR/bin"
    if [ -f "$MIHOMO_BIN" ]; then
        cp "$MIHOMO_BIN" "${MIHOMO_BIN}.bak"
        log_info "旧 mihomo 二进制已备份到 ${MIHOMO_BIN}.bak"
    fi
    gzip -dc "${tmpdir}/${asset}" > "${MIHOMO_BIN}.new"
    chmod 755 "${MIHOMO_BIN}.new"
    local size=0
    size="$(stat -c %s "${MIHOMO_BIN}.new")"
    if [ "$size" -lt 10000000 ]; then
        rm -f "${MIHOMO_BIN}.new"
        die "mihomo 解压后体积异常（${size} 字节），安装中止。"
    fi
    local version_out=""
    version_out="$("${MIHOMO_BIN}.new" -v 2>&1)" || die "mihomo 烟囱测试失败（无法运行解压出的二进制），安装中止。"
    if ! printf '%s' "$version_out" | grep -q "$MIHOMO_VERSION"; then
        rm -f "${MIHOMO_BIN}.new"
        die "mihomo 版本不符：期望 v${MIHOMO_VERSION}，实际输出：${version_out}"
    fi
    mv "${MIHOMO_BIN}.new" "$MIHOMO_BIN"
    log_ok "mihomo 安装完成：$version_out"
    trap - EXIT
    rm -rf "$tmpdir"
}

install_metacubexd() {
    if [ -z "$EXTERNAL_UI" ]; then
        log_info "跳过 metacubexd（LANMUX_EXTERNAL_UI=none）"
        return 0
    fi
    log_info "安装 metacubexd v${METACUBEXD_VERSION}"
    local url="https://github.com/MetaCubeX/metacubexd/releases/download/v${METACUBEXD_VERSION}/compressed-dist.tgz"
    local tmpdir=""
    tmpdir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" EXIT
    download_with_mirrors "$url" "${tmpdir}/compressed-dist.tgz" 1000000 "metacubexd" 300 "${MIHOMO_MIRROR:-}"
    # H-13：整包 SHA256 强制校验（覆盖解压后的全部文件，比只验
    # index.html 存在更强）；不匹配即中止，不解压、不安装。
    verify_sha256 "${tmpdir}/compressed-dist.tgz" "compressed-dist.tgz" "metacubexd"
    mkdir -p "${tmpdir}/ui"
    tar -xzf "${tmpdir}/compressed-dist.tgz" -C "${tmpdir}/ui"
    if [ ! -f "${tmpdir}/ui/index.html" ]; then
        # 兜底：若某版 tarball 多了一层目录，把含 index.html 的那层提上来。
        local subdir=""
        subdir="$(find "${tmpdir}/ui" -maxdepth 2 -name index.html -printf '%h\n' 2>/dev/null | head -n 1)"
        if [ -n "$subdir" ] && [ "$subdir" != "${tmpdir}/ui" ]; then
            mv "${subdir}"/* "${tmpdir}/ui/" 2>/dev/null || true
        fi
    fi
    if [ ! -f "${tmpdir}/ui/index.html" ]; then
        die "metacubexd 解压后找不到 index.html，安装中止。"
    fi
    safe_rm_rf "$EXTERNAL_UI"
    mkdir -p "$(dirname -- "$EXTERNAL_UI")"
    mv "${tmpdir}/ui" "$EXTERNAL_UI"
    log_ok "metacubexd 安装完成：$EXTERNAL_UI"
    trap - EXIT
    rm -rf "$tmpdir"
}

install_geodata() {
    log_info "预置 geodata（GeoIP / GeoSite / Country.mmdb，mihomo 启动时不再联网拉取）"
    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    local asset=""
    local target=""
    local url=""
    for asset in "geoip.dat:GeoIP.dat" "geosite.dat:GeoSite.dat" "country.mmdb:Country.mmdb"; do
        target="${DATA_DIR}/${asset##*:}"
        asset="${asset%%:*}"
        # PR-34：已存在文件不再只看体积跳过，必须 SHA256 校验通过才
        # 跳过；损坏/被篡改（哈希不符）即重新下载。清单缺失时
        # verify_existing_sha256 直接 die（fail-closed）。
        if [ "${LANMUX_REFRESH_GEODATA:-0}" != "1" ] && [ -f "$target" ]; then
            if verify_existing_sha256 "$target" "$asset" "geodata ${asset}"; then
                continue
            fi
        fi
        # 注意：上游 MetaCubeX/meta-rules-dat 只有一个滚动发布，tag 字面
        # 就是 "latest"，无固定 tag 可钉（见 scripts/asset-checksums.sha256
        # 头部说明）；URL 里的 latest 只定位到该发布，内容由下面的
        # SHA256 钉死——上游滚动更新后旧哈希会明确报错，不会静默换内容。
        url="https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/${asset}"
        download_with_mirrors "$url" "$target" 1000000 "geodata ${asset}" 300 "${GEODATA_MIRROR:-}"
        verify_sha256 "$target" "$asset" "geodata ${asset}"
    done
    log_ok "geodata 预置完成"
}

install_code() {
    log_info "部署后端与前端到 $INSTALL_DIR"
    mkdir -p "$BACKEND_DIR" "$INSTALL_DIR/frontend"
    safe_rm_rf "$BACKEND_DIR/app"
    cp -r "$SCRIPT_DIR/backend/app" "$BACKEND_DIR/app"
    # Pinned, hashed production dependencies (audit M-45): the lockfile is
    # the install input; requirements-prod.txt is only the floor manifest
    # used to regenerate it (pip-compile --generate-hashes).
    cp "$SCRIPT_DIR/backend/requirements-prod.lock" "$BACKEND_DIR/requirements-prod.lock"
    cp -r "$SCRIPT_DIR/frontend/." "$INSTALL_DIR/frontend/"
    # 卸载脚本也装一份到安装目录：删了仓库 checkout 也能卸载。
    cp "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
    chmod 755 "$INSTALL_DIR/uninstall.sh"
    find "$BACKEND_DIR" "$INSTALL_DIR/frontend" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
    log_ok "代码部署完成"
}

install_venv() {
    log_info "准备 Python 虚拟环境"
    # 半残 venv 必须重建：首跑 ensurepip 失败会留下带 bin/python 但无 pip 的
    # 目录，只测 python 会误判为可用，后续 pip 命令直接报 No such file。
    if [ ! -x "$VENV_DIR/bin/python" ] || [ ! -x "$VENV_DIR/bin/pip" ]; then
        safe_rm_rf "$VENV_DIR"
        "$PYBIN" -m venv "$VENV_DIR" \
            || die "venv 创建失败。请手动执行：sudo apt-get install -y ${PYBIN}-venv，然后重跑安装。"
    fi
    if [ ! -x "$VENV_DIR/bin/pip" ]; then
        die "venv 创建后仍无 pip 可用。请手动执行：sudo apt-get install -y ${PYBIN}-venv，然后重跑安装。"
    fi
    if ! "$VENV_DIR/bin/pip" install --quiet --require-hashes -r "$BACKEND_DIR/requirements-prod.lock"; then
        echo "[ERROR] Python 依赖安装失败（可能是 PyPI 网络问题）。可指定镜像源重跑：" >&2
        echo "        PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple sudo -E bash install.sh" >&2
        exit 1
    fi
    log_ok "Python 依赖安装完成"
}

converge_data_perms() {
    # M-08 / PR-11：安装/升级时把已存在的数据目录与敏感文件收敛到
    # 0700 / 0600（升级保留的旧文件可能是 umask 022 下建的 0644）。
    # 只收敛已存在的文件，不创建新文件；单项失败不致命（启动时
    # Database 也会再收敛 DB 一次），但目录本身收敛失败要报错。
    # 注意：config.yaml / .bak 写盘时的 0600 由后端原子写保证，
    # 这里只做安装期的兜底收敛。
    if [ ! -d "$DATA_DIR" ]; then
        return 0
    fi
    chmod 700 "$DATA_DIR"
    local f=""
    for f in lanmux.db lanmux.db-journal lanmux.db-wal lanmux.db-shm \
             config.yaml config.yaml.bak lanmux.env; do
        if [ -e "$DATA_DIR/$f" ]; then
            chmod 600 "$DATA_DIR/$f" 2>/dev/null || true
        fi
    done
}

write_lanmux_env() {
    log_info "写入 $LANMUX_ENV（600 权限，仅 root 可读）"
    mkdir -p "$DATA_DIR"
    chmod 700 "$DATA_DIR"
    # 先删残留的 .new：shell 重定向会保留已存在文件的旧权限，
    # 残留的 0644 .new 会让下面的 umask 077 白做。
    rm -f "${LANMUX_ENV}.new"
    # L-24：写盘在 umask 077 的子 shell 里做，.new 从创建那一刻起
    # 就是 0600，不再有“先 644 落盘、再 chmod 600”的泄漏窗口。
    # 子 shell 用完即弃，umask 不会漏到脚本其余部分。
    (
        umask 077
        {
            echo "# LanMux — 安装器生成，改密码请走网页设置，不要手改这里。"
            echo "# 升级重跑安装器时会重写本文件（密码类取值来自已存设置，不会被覆盖）。"
            printf 'ADMIN_PASSWORD=%s\n' "$(env_quote "$ADMIN_PASSWORD")"
            printf 'MIHOMO_SECRET=%s\n' "$(env_quote "$MIHOMO_SECRET")"
            printf 'SS_PASSWORD=%s\n' "$(env_quote "$SS_PASSWORD")"
            printf 'SS_CIPHER=%s\n' "$(env_quote "$SS_CIPHER")"
            printf 'LANMUX_LAN_IP=%s\n' "$(env_quote "$LAN_IP")"
            printf 'LANMUX_SS_PORT=%s\n' "$(env_quote "$SS_PORT")"
            printf 'LANMUX_MIXED_PORT=%s\n' "$(env_quote "$MIXED_PORT")"
            printf 'LANMUX_MIXED_AUTH_USER=%s\n' "$(env_quote "$MIXED_AUTH_USER")"
            printf 'LANMUX_MIXED_AUTH_PASS=%s\n' "$(env_quote "$MIXED_AUTH_PASS")"
            printf 'LANMUX_CONTROLLER_PORT=%s\n' "$(env_quote "$CONTROLLER_PORT")"
            printf 'LANMUX_WEB_PORT=%s\n' "$(env_quote "$WEB_PORT")"
            printf 'LANMUX_EXTERNAL_UI=%s\n' "$(env_quote "$EXTERNAL_UI")"
            printf 'LANMUX_DB_PATH=%s\n' "$(env_quote "$DB_PATH")"
            printf 'LANMUX_CONFIG_PATH=%s\n' "$(env_quote "$CONFIG_PATH")"
            printf 'MIHOMO_BASE_URL=%s\n' "$(env_quote "http://127.0.0.1:{port}")"
        } > "${LANMUX_ENV}.new"
    )
    chmod 600 "${LANMUX_ENV}.new"
    mv "${LANMUX_ENV}.new" "$LANMUX_ENV"
    # 写完校验：落盘文件必须确为 600，否则中止安装。
    local perm=""
    perm="$(stat -c %a "$LANMUX_ENV")"
    if [ "$perm" != "600" ]; then
        die "lanmux.env 权限异常（期望 600，实际 $perm），安装中止"
    fi
    log_ok "lanmux.env 已写入"
}

generate_config() {
    log_info "生成初始 mihomo 配置（零节点时各组指向 DIRECT，冷启动保护）"
    if ! (cd "$BACKEND_DIR" && env -i PATH="/usr/bin:/bin" \
        LANMUX_DB_PATH="$DB_PATH" LANMUX_CONFIG_PATH="$CONFIG_PATH" \
        ADMIN_PASSWORD="$ADMIN_PASSWORD" MIHOMO_SECRET="$MIHOMO_SECRET" \
        SS_PASSWORD="$SS_PASSWORD" SS_CIPHER="$SS_CIPHER" LANMUX_LAN_IP="$LAN_IP" \
        LANMUX_SS_PORT="$SS_PORT" LANMUX_MIXED_PORT="$MIXED_PORT" \
        LANMUX_CONTROLLER_PORT="$CONTROLLER_PORT" \
        LANMUX_MIXED_AUTH_USER="$MIXED_AUTH_USER" LANMUX_MIXED_AUTH_PASS="$MIXED_AUTH_PASS" \
        LANMUX_EXTERNAL_UI="$EXTERNAL_UI" \
        "$VENV_DIR/bin/python" -m app.init_lanmux --apply-env); then
        die "初始配置生成失败（见上方 init_lanmux 报错），安装中止。"
    fi
    log_info "用 mihomo 自身校验生成的配置"
    if ! "$MIHOMO_BIN" -t -d "$DATA_DIR" -f "$CONFIG_PATH" 2>&1 | tail -n 5; then
        die "mihomo 拒绝生成的配置（见上方输出），安装中止。"
    fi
    log_ok "配置校验通过：$CONFIG_PATH"
}

ensure_service_user() {
    log_info "创建专用低权用户 $LANMUX_USER（systemd 单元以该用户运行）"
    if id -u "$LANMUX_USER" >/dev/null 2>&1; then
        log_ok "用户 $LANMUX_USER 已存在（uid=$(id -u "$LANMUX_USER")），跳过创建"
        return 0
    fi
    if ! useradd --system --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$LANMUX_USER"; then
        die "创建系统用户 $LANMUX_USER 失败（需要 useradd；Debian/Ubuntu 默认自带）"
    fi
    log_ok "已创建系统用户 $LANMUX_USER"
}

chown_data_dir() {
    # 数据目录属主交给 lanmux：systemd 服务以该用户读写 config.yaml
    # （含 .tmp/.bak）、lanmux.db（含 SQLite journal）、geodata 与 ui/。
    # 注意：只改属主，不改目录与文件权限（DB/config.yaml 的 0600 收敛
    # 是另一簇的事）；程序目录 /opt/lanmux 保持 root 属主 755，服务只
    # 需读与执行。必须在 generate_config 之后调（之前创建的文件属主
    # 还是 root），在 start_services 之前调。
    log_info "把数据目录 $DATA_DIR 属主交给 $LANMUX_USER"
    mkdir -p "$DATA_DIR"
    chown -R "$LANMUX_USER:$LANMUX_USER" "$DATA_DIR"
    log_ok "数据目录属主已设为 $LANMUX_USER"
}

install_units() {
    log_info "安装 systemd 单元（lanmux-mihomo / lanmux-web，绝不碰 mihomo 单元）"
    # /etc/systemd/system 在真实系统上恒存在；mkdir -p 是防御性兜底，
    # 也让 sed 改写路径后的 stub-run 能跑通。
    mkdir -p "$SYSTEMD_DIR"
    local unit=""
    local tmp=""
    for unit in lanmux-mihomo.service lanmux-web.service; do
        if [ ! -f "$SCRIPT_DIR/systemd/$unit" ]; then
            die "单元模板缺失：$SCRIPT_DIR/systemd/$unit 不存在，无法安装 systemd 单元（请确认仓库完整克隆）"
        fi
        tmp="$(mktemp)"
        sed -e "s|/opt/lanmux|$INSTALL_DIR|g" \
            -e "s|/etc/lanmux|$DATA_DIR|g" \
            "$SCRIPT_DIR/systemd/$unit" > "$tmp"
        cp "$tmp" "$SYSTEMD_DIR/$unit"
        rm -f "$tmp"
        log_ok "已安装 $SYSTEMD_DIR/$unit"
    done
    systemctl daemon-reload
    systemctl enable lanmux-mihomo.service lanmux-web.service >/dev/null
    log_ok "单元已启用（开机自启）"
}

wait_for_http() {
    # wait_for_http <url> <timeout秒> <说明> [bearer token]
    local url="$1"
    local timeout="$2"
    local label="$3"
    local token="${4:-}"
    local i=0
    while [ "$i" -lt "$timeout" ]; do
        if [ -n "$token" ]; then
            if curl -fsS -o /dev/null -H "Authorization: Bearer $token" --max-time 5 "$url" 2>/dev/null; then
                return 0
            fi
        else
            if curl -fsS -o /dev/null --max-time 5 "$url" 2>/dev/null; then
                return 0
            fi
        fi
        sleep 1
        i=$((i + 1))
    done
    log_warn "${label} 在 ${timeout} 秒内未就绪：$url"
    return 1
}

start_services() {
    log_info "启动 lanmux-mihomo"
    systemctl restart lanmux-mihomo.service
    local secret=""
    secret="$(db_setting "mihomo_secret")"
    if ! wait_for_http "http://127.0.0.1:${CONTROLLER_PORT}/version" 30 "mihomo 控制器" "$secret"; then
        echo "[ERROR] lanmux-mihomo 启动失败，最近日志：" >&2
        systemctl status lanmux-mihomo.service --no-pager -l 2>/dev/null | head -n 20 >&2 || true
        journalctl -u lanmux-mihomo.service --no-pager -n 50 2>/dev/null >&2 || true
        echo "        若因二进制问题失败，可手动回滚旧版：cp ${MIHOMO_BIN}.bak $MIHOMO_BIN && systemctl restart lanmux-mihomo" >&2
        exit 1
    fi
    log_ok "mihomo 控制器就绪"
    log_info "启动 lanmux-web"
    systemctl restart lanmux-web.service
    if ! wait_for_http "http://127.0.0.1:${WEB_PORT}/health" 30 "lanmux-web 面板"; then
        echo "[ERROR] lanmux-web 启动失败，最近日志：" >&2
        journalctl -u lanmux-web.service --no-pager -n 50 2>/dev/null >&2 || true
        exit 1
    fi
    log_ok "lanmux-web 面板就绪"
}

print_summary() {
    echo ""
    echo "========================================"
    if [ "$UPGRADE_MODE" -eq 1 ]; then
        echo "LanMux v${LANMUX_VERSION} 升级完成"
    else
        echo "LanMux v${LANMUX_VERSION} 安装完成"
    fi
    echo "========================================"
    echo "管理面板：  http://${LAN_IP}:${WEB_PORT}/"
    echo "SS 总节点： ${LAN_IP}:${SS_PORT}（${SS_CIPHER}），面板总节点卡片可复制链接/扫码"
    echo "Mixed 入口：http://${LAN_IP}:${MIXED_PORT}（HTTP/SOCKS5，UDP 已开）"
    if [ -n "$EXTERNAL_UI" ]; then
        echo "Metacubexd： http://${LAN_IP}:${CONTROLLER_PORT}/ui/（看详细连接日志）"
    fi
    echo ""
    if [ "$UPGRADE_MODE" -eq 0 ]; then
        if [ -n "$ADMIN_PASSWORD" ]; then
            echo "请登录面板后在 设置 里改掉默认管理员密码与 SS 密码。"
        else
            echo "首次打开面板时请按向导设置管理员密码。"
        fi
    fi
    echo "验收命令：  bash $SCRIPT_DIR/scripts/verify.sh"
    echo "升级命令：  cd $SCRIPT_DIR && git fetch origin && git reset --hard origin/main && sudo bash install.sh"
    echo "卸载命令：  sudo bash $INSTALL_DIR/uninstall.sh"
    echo "服务状态：  systemctl status lanmux-mihomo lanmux-web"
    echo "========================================"
}

# ------------------------------------------------------------------ 主流程
usage() {
    echo "用法：sudo bash install.sh [--non-interactive] [--help]"
    echo "  交互式安装/升级：sudo bash install.sh"
    echo "  非交互式：       sudo bash install.sh --non-interactive（取值来自环境变量；密码请用 LANMUX_INSTALL_ENV_FILE=<600 权限文件> 传入，不要写进命令行）"
    echo "  卸载请用：       sudo bash uninstall.sh"
}

migrate_legacy_install() {
    # migrate_legacy_install — v0.9.0 改名迁移（LAN Proxy Hub -> LanMux）。
    # 升级模式：旧数据目录整体搬到新路径，内部文件改名（hub.db/hub.env ->
    # lanmux.db/lanmux.env），env 文件键名 HUB_ -> LANMUX_、路径值旧 -> 新，
    # DB 里的 external_ui 指向新 ui 路径；旧单元停用删除，旧程序目录删除。
    # 节点、规则、设置、密码全部保留。
    # 全新安装模式：只停旧服务、删旧目录与旧单元（数据本来就要清空）。
    # 幂等：无旧名残留时直接返回；新旧数据目录并存时不动旧目录（防误伤，
    # 这种情况只在旧版安装器又跑过一次后出现，需手动处理）。
    # 新目录下的 hub.db/hub.env 是上次迁移中途的半成品（mv 已成、改名未
    # 做），继续把它改名并修正 external_ui。
    local have_legacy=0
    if [ -d "$LEGACY_DATA_DIR" ] || [ -d "$LEGACY_INSTALL_DIR" ] \
        || [ -f "$SYSTEMD_DIR/hub-mihomo.service" ] \
        || [ -f "$SYSTEMD_DIR/hub-web.service" ] \
        || [ -f "$DATA_DIR/hub.db" ] || [ -f "$DATA_DIR/hub.env" ]; then
        have_legacy=1
    fi
    if [ "$have_legacy" -eq 0 ]; then
        return 0
    fi
    if [ -d "$DATA_DIR" ] && [ ! -f "$DATA_DIR/hub.db" ] && [ ! -f "$DATA_DIR/hub.env" ] \
        && [ -d "$LEGACY_DATA_DIR" ]; then
        log_warn "检测到旧名残留（$LEGACY_DATA_DIR），但新数据目录已存在，跳过迁移（旧目录请手动处理）"
        return 0
    fi
    # 先停旧服务（旧单元指向旧路径，动目录前必须停）。
    systemctl stop hub-mihomo.service hub-web.service 2>/dev/null || true
    systemctl disable hub-mihomo.service hub-web.service 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/hub-mihomo.service" "$SYSTEMD_DIR/hub-web.service"
    if [ "$UPGRADE_MODE" -eq 0 ]; then
        # 全新安装：数据本来就要清空，只删旧目录（删前同样校验标记+备份）。
        if [ -d "$LEGACY_DATA_DIR" ]; then
            require_lanmux_marker "$LEGACY_DATA_DIR" hub.db hub.env lanmux.db lanmux.env config.yaml
            backup_data_dir "$LEGACY_DATA_DIR"
            safe_rm_rf "$LEGACY_DATA_DIR"
        fi
        if [ -d "$LEGACY_INSTALL_DIR" ]; then
            require_lanmux_marker "$LEGACY_INSTALL_DIR" backend bin frontend venv uninstall.sh
            safe_rm_rf "$LEGACY_INSTALL_DIR"
        fi
        log_ok "旧名残留已清理（全新安装模式）"
        systemctl daemon-reload 2>/dev/null || true
        return 0
    fi
    log_info "检测到旧名安装（LAN Proxy Hub），正在迁移到 LanMux（数据、节点、密码全部保留）..."
    if [ -d "$LEGACY_DATA_DIR" ]; then
        mv "$LEGACY_DATA_DIR" "$DATA_DIR"
        log_ok "数据目录已迁移：$LEGACY_DATA_DIR -> $DATA_DIR"
    fi
    if [ -f "$DATA_DIR/hub.db" ]; then
        mv "$DATA_DIR/hub.db" "$DATA_DIR/lanmux.db"
    fi
    if [ -f "$DATA_DIR/hub.env" ]; then
        mv "$DATA_DIR/hub.env" "$DATA_DIR/lanmux.env"
    fi
    if [ -f "$LANMUX_ENV" ]; then
        # env 文件：键名 LANMUX_ 化（只改行首键名，不动值），路径值旧 -> 新。
        # 文件名也要改（fenliu.db/fenliu.env 已改名为 lanmux.db/lanmux.env），
        # 否则 env 里的 LANMUX_DB_PATH 会指向一个不存在的文件。
        sed -i -e 's/^HUB_/LANMUX_/' \
               -e 's|/opt/lan-proxy-hub|/opt/lanmux|g' \
               -e 's|/etc/lan-proxy-hub|/etc/lanmux|g' \
               -e 's|hub\.db|lanmux.db|g' \
               -e 's|hub\.env|lanmux.env|g' \
            "$LANMUX_ENV"
    fi
    if [ -f "$DB_PATH" ]; then
        # DB 里的 external_ui 指向旧 ui 路径，改到新路径（否则面板里的
        # metacubexd 入口 404）。直连 sqlite，不依赖 venv（此时还没建好）。
        if ! python3 - "$DB_PATH" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("SELECT value FROM settings WHERE key='external_ui'").fetchone()
if row and row[0] and row[0].startswith('/etc/lan-proxy-hub'):
    new = row[0].replace('/etc/lan-proxy-hub', '/etc/lanmux', 1)
    db.execute("UPDATE settings SET value=? WHERE key='external_ui'", (new,))
    db.commit()
    print(f"external_ui 已迁移: {row[0]} -> {new}")
db.close()
PYEOF
        then
            log_warn "external_ui 路径修正失败（可进面板设置里手动改回 $DATA_DIR/ui）"
        fi
    fi
    if [ -d "$LEGACY_INSTALL_DIR" ]; then
        require_lanmux_marker "$LEGACY_INSTALL_DIR" backend bin frontend venv uninstall.sh
        safe_rm_rf "$LEGACY_INSTALL_DIR"
        log_ok "旧程序目录已删除：$LEGACY_INSTALL_DIR"
    fi
    systemctl daemon-reload 2>/dev/null || true
    log_ok "旧名迁移完成"
}

migrate_lanmux_install() {
    # migrate_lanmux_install — v1.0.0 改名迁移（Fenliu -> LanMux）。
    # 与 migrate_legacy_install 同套路：升级模式下旧数据目录搬到新路径，
    # 内部文件改名（fenliu.db/fenliu.env -> lanmux.db/lanmux.env），env
    # 文件键名 FENLIU_ -> LANMUX_（HUB_ 残留同样改）、路径值旧 -> 新，
    # DB 里的 external_ui 指向新 ui 路径；旧单元停用删除，旧程序目录删除。
    # 节点、规则、设置、密码全部保留。
    # 全新安装模式：只停旧服务、删旧目录与旧单元（数据本来就要清空）。
    # 幂等：无旧名残留时直接返回；新旧数据目录并存时不动已迁移的数据
    # （只逐文件搬缺失项，已有文件绝不覆盖；旧目录搬空后才删）。
    # 新目录下的 fenliu.db/fenliu.env 是上次迁移中途的半成品（mv 已成、
    # 改名未做），继续把它改名并修正 external_ui。
    local have_legacy=0
    if [ -d "$LEGACY_FENLIU_DATA_DIR" ] || [ -d "$LEGACY_FENLIU_INSTALL_DIR" ] \
        || [ -f "$SYSTEMD_DIR/fenliu-mihomo.service" ] \
        || [ -f "$SYSTEMD_DIR/fenliu-web.service" ] \
        || [ -f "$DATA_DIR/fenliu.db" ] || [ -f "$DATA_DIR/fenliu.env" ]; then
        have_legacy=1
    fi
    if [ "$have_legacy" -eq 0 ]; then
        return 0
    fi
    if [ -d "$DATA_DIR" ] && [ ! -f "$DATA_DIR/fenliu.db" ] && [ ! -f "$DATA_DIR/fenliu.env" ] \
        && [ -d "$LEGACY_FENLIU_DATA_DIR" ]; then
        log_warn "检测到旧名残留（$LEGACY_FENLIU_DATA_DIR），但新数据目录已存在，跳过迁移（旧目录请手动处理）"
        return 0
    fi
    # 先停旧服务（旧单元指向旧路径，动目录前必须停）。
    systemctl stop fenliu-mihomo.service fenliu-web.service 2>/dev/null || true
    systemctl disable fenliu-mihomo.service fenliu-web.service 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/fenliu-mihomo.service" "$SYSTEMD_DIR/fenliu-web.service"
    if [ "$UPGRADE_MODE" -eq 0 ]; then
        # 全新安装：数据本来就要清空，只删旧目录（删前同样校验标记+备份）。
        if [ -d "$LEGACY_FENLIU_DATA_DIR" ]; then
            require_lanmux_marker "$LEGACY_FENLIU_DATA_DIR" fenliu.db fenliu.env hub.db hub.env lanmux.db lanmux.env config.yaml
            backup_data_dir "$LEGACY_FENLIU_DATA_DIR"
            safe_rm_rf "$LEGACY_FENLIU_DATA_DIR"
        fi
        if [ -d "$LEGACY_FENLIU_INSTALL_DIR" ]; then
            require_lanmux_marker "$LEGACY_FENLIU_INSTALL_DIR" backend bin frontend venv uninstall.sh
            safe_rm_rf "$LEGACY_FENLIU_INSTALL_DIR"
        fi
        log_ok "旧名残留已清理（全新安装模式）"
        systemctl daemon-reload 2>/dev/null || true
        return 0
    fi
    log_info "检测到旧名安装（Fenliu），正在迁移到 LanMux（数据、节点、密码全部保留）..."
    if [ -d "$LEGACY_FENLIU_DATA_DIR" ]; then
        if [ -d "$DATA_DIR" ]; then
            # 新目录已存在（上次迁移的半成品）：逐文件搬缺失项，已有文件
            # 绝不覆盖；目录 mv 在目标已存在时会嵌套成子目录，绝不能用。
            local f=""
            local base=""
            for f in "$LEGACY_FENLIU_DATA_DIR"/*; do
                [ -e "$f" ] || continue
                base="$(basename "$f")"
                if [ ! -e "$DATA_DIR/$base" ]; then
                    mv "$f" "$DATA_DIR/$base"
                fi
            done
            rmdir "$LEGACY_FENLIU_DATA_DIR" 2>/dev/null || true
            log_ok "数据文件已迁移：$LEGACY_FENLIU_DATA_DIR -> $DATA_DIR（逐文件，已有文件未覆盖）"
        else
            mv "$LEGACY_FENLIU_DATA_DIR" "$DATA_DIR"
            log_ok "数据目录已迁移：$LEGACY_FENLIU_DATA_DIR -> $DATA_DIR"
        fi
    fi
    if [ -f "$DATA_DIR/fenliu.db" ]; then
        mv "$DATA_DIR/fenliu.db" "$DATA_DIR/lanmux.db"
    fi
    if [ -f "$DATA_DIR/fenliu.env" ]; then
        mv "$DATA_DIR/fenliu.env" "$DATA_DIR/lanmux.env"
    fi
    if [ -f "$LANMUX_ENV" ]; then
        # env 文件：键名 LANMUX_ 化（只改行首键名，不动值），路径值旧 -> 新。
        # 文件名也要改（fenliu.db/fenliu.env 已改名为 lanmux.db/lanmux.env），
        # 否则 env 里的 LANMUX_DB_PATH 会指向一个不存在的文件。
        sed -i -e 's/^FENLIU_/LANMUX_/' \
               -e 's/^HUB_/LANMUX_/' \
               -e 's|/opt/fenliu|/opt/lanmux|g' \
               -e 's|/etc/fenliu|/etc/lanmux|g' \
               -e 's|fenliu\.db|lanmux.db|g' \
               -e 's|fenliu\.env|lanmux.env|g' \
            "$LANMUX_ENV"
    fi
    if [ -f "$DB_PATH" ]; then
        # DB 里的 external_ui 指向旧 ui 路径，改到新路径（否则面板里的
        # metacubexd 入口 404）。直连 sqlite，不依赖 venv（此时还没建好）。
        if ! python3 - "$DB_PATH" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
row = db.execute("SELECT value FROM settings WHERE key='external_ui'").fetchone()
if row and row[0] and row[0].startswith('/etc/fenliu'):
    new = row[0].replace('/etc/fenliu', '/etc/lanmux', 1)
    db.execute("UPDATE settings SET value=? WHERE key='external_ui'", (new,))
    db.commit()
    print(f"external_ui 已迁移: {row[0]} -> {new}")
db.close()
PYEOF
        then
            log_warn "external_ui 路径修正失败（可进面板设置里手动改回 $DATA_DIR/ui）"
        fi
    fi
    if [ -d "$LEGACY_FENLIU_INSTALL_DIR" ]; then
        require_lanmux_marker "$LEGACY_FENLIU_INSTALL_DIR" backend bin frontend venv uninstall.sh
        safe_rm_rf "$LEGACY_FENLIU_INSTALL_DIR"
        log_ok "旧程序目录已删除：$LEGACY_FENLIU_INSTALL_DIR"
    fi
    systemctl daemon-reload 2>/dev/null || true
    log_ok "旧名迁移完成"
}

main() {
    local arg=""
    for arg in "$@"; do
        case "$arg" in
            install|upgrade)
                ;;
            --non-interactive)
                NONINTERACTIVE=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            uninstall)
                die "卸载请用 uninstall.sh，不要用 install.sh。"
                ;;
            *)
                echo "[ERROR] 未知参数：$arg" >&2
                usage >&2
                exit 1
                ;;
        esac
    done
    if [ ! -t 0 ] && [ "$NONINTERACTIVE" -eq 0 ]; then
        log_info "检测到非终端输入，自动切换为非交互模式"
        NONINTERACTIVE=1
    fi

    preflight_env

    # 先建运行用户：后续 chown_data_dir 与 install_units（单元含
    # User=lanmux）都依赖它；失败时尽早中止，不做任何修改。
    ensure_service_user

    # 模式先定：有已存数据即升级模式（保留数据）；全新安装需显式确认。
    # 旧名残留也算已有安装（迁移在模式决定后做，取消时不做任何修改）。
    # 新目录下的 hub.db/hub.env 是上次迁移中途的半成品，同样算已有安装；
    # /etc/fenliu 下的 fenliu.db/fenliu.env（或半成品 hub.db/hub.env）
    # 是 v1.0.0 改名前 Fenliu 时代的安装，同样算已有安装。
    if [ -f "$DB_PATH" ] || [ -f "$LANMUX_ENV" ] \
        || [ -f "$DATA_DIR/hub.db" ] || [ -f "$DATA_DIR/hub.env" ] \
        || [ -f "$LEGACY_DATA_DIR/hub.db" ] || [ -f "$LEGACY_DATA_DIR/hub.env" ] \
        || [ -f "$LEGACY_FENLIU_DATA_DIR/fenliu.db" ] || [ -f "$LEGACY_FENLIU_DATA_DIR/fenliu.env" ] \
        || [ -f "$LEGACY_FENLIU_DATA_DIR/hub.db" ] || [ -f "$LEGACY_FENLIU_DATA_DIR/hub.env" ]; then
        HAVE_EXISTING_INSTALL=1
    fi
    if [ "$HAVE_EXISTING_INSTALL" -eq 1 ]; then
        if [ "$FRESH_INSTALL" = "1" ]; then
            check_fresh_install_confirm
            UPGRADE_MODE=0
            log_warn "全新安装模式（LANMUX_FRESH_INSTALL=1，已二次确认 LANMUX_FRESH_INSTALL_CONFIRM=1）：将清空已有数据，清空前自动备份"
        elif [ "$NONINTERACTIVE" -eq 1 ]; then
            UPGRADE_MODE=1
            log_info "检测到已有安装，非交互模式下默认升级（保留数据）"
        else
            echo ""
            echo "检测到已有安装（$DB_PATH），请选择模式："
            echo "  [1] 升级（保留节点、规则、设置与密码，只更新程序与二进制）[默认]"
            echo "  [2] 全新安装（清空全部数据重来）"
            local mode_answer=""
            printf '请选择 [1/2]：'
            if ! read -r mode_answer; then
                echo ""
                die "输入中断，安装已取消（未做任何修改）。"
            fi
            case "$mode_answer" in
                2)
                    local wipe_answer=""
                    printf '全新安装将删除 %s 与 %s，确认请输入 YES：' "$DB_PATH" "$CONFIG_PATH"
                    if ! read -r wipe_answer; then
                        echo ""
                        die "输入中断，安装已取消（未做任何修改）。"
                    fi
                    if [ "$wipe_answer" != "YES" ]; then
                        echo "已取消，未做任何修改。"
                        exit 0
                    fi
                    UPGRADE_MODE=0
                    ;;
                *)
                    UPGRADE_MODE=1
                    ;;
            esac
        fi
    else
        UPGRADE_MODE=0
    fi
    if [ "$UPGRADE_MODE" -eq 1 ]; then
        log_info "升级模式：保留节点、规则、设置与全部密码，只更新程序、二进制与面板"
    fi

    # 旧名迁移（v0.9.0 改名 + v1.0.0 改名）：必须在模式决定之后、
    # 清数据之前做。交互取消时上面的 die/exit 已返回，迁移不会运行，
    # 不做任何修改。先迁 LAN Proxy Hub，再迁 Fenliu。
    migrate_legacy_install
    migrate_lanmux_install

    # 全新安装覆盖已有数据时，先停服务、校验标记、自动备份，再清数据。
    if [ "$UPGRADE_MODE" -eq 0 ] && [ "$HAVE_EXISTING_INSTALL" -eq 1 ]; then
        log_warn "清空已有数据：停止服务并删除 $DATA_DIR"
        systemctl stop lanmux-mihomo.service lanmux-web.service 2>/dev/null || true
        systemctl disable lanmux-mihomo.service lanmux-web.service 2>/dev/null || true
        require_lanmux_marker "$DATA_DIR" lanmux.env lanmux.db config.yaml hub.db hub.env fenliu.db fenliu.env
        backup_data_dir "$DATA_DIR"
        safe_rm_rf "$DATA_DIR"
    fi

    resolve_defaults
    if [ "$NONINTERACTIVE" -eq 1 ]; then
        # 非交互：缺失的密码自动生成（管理员密码缺失则走网页向导）。
        if [ "$UPGRADE_MODE" -eq 0 ]; then
            if [ -z "$SS_PASSWORD" ]; then
                SS_PASSWORD="$(random_password 16)"
                log_info "SS 密码未提供，已随机生成（装好后在面板总节点卡片查看/复制）"
            fi
            if [ -z "$MIHOMO_SECRET" ]; then
                MIHOMO_SECRET="$(random_hex 24)"
            fi
            if [ -z "$ADMIN_PASSWORD" ]; then
                log_warn "未提供 ADMIN_PASSWORD：首次打开面板时请按向导设置管理员密码"
            fi
        fi
    fi
    confirm_loop

    install_deps
    install_mihomo
    install_metacubexd
    install_geodata
    install_code
    install_venv
    write_lanmux_env
    generate_config
    # Both: chown hands the data dir to the lanmux service user
    # (nonroot), then converge_data_perms tightens modes to 0700/0600
    # (file-perms). The two only touch ownership vs modes, so order
    # is free; ownership first reads naturally.
    chown_data_dir
    converge_data_perms
    install_units
    start_services
    print_summary
}

main "$@"
