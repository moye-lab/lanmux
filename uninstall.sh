#!/usr/bin/env bash
# LanMux — 卸载脚本。
#
# 用法：sudo bash uninstall.sh
#   交互式：停服务、删单元与程序，并询问是否保留 /etc/lanmux
#   下的数据（config.yaml、lanmux.db、lanmux.env）。
#   非交互式：LANMUX_NONINTERACTIVE=1 LANMUX_UNINSTALL_KEEP_DATA=0 sudo -E bash uninstall.sh
#
# 本脚本绝不碰：/etc/mihomo 与 mihomo 单元（用户旧 mihomo-gateway 的
# 东西）、docker。只删 LanMux 自己的 lanmux-mihomo / lanmux-web 单元、
# /opt/lanmux 程序目录，以及（用户确认后）/etc/lanmux。
#
# 环境变量：
#   LANMUX_NONINTERACTIVE=1       非交互模式
#   LANMUX_UNINSTALL_KEEP_DATA    1=保留数据（默认）/ 0=一并删除
#   LANMUX_INSTALL_DIR / LANMUX_DATA_DIR / LANMUX_SYSTEMD_DIR  路径覆盖（仅供测试）
#
# 安全护栏（H-14）：路径覆盖只允许 LanMux 自己的目录（/opt/lanmux、
# /etc/lanmux、/var/lib/lanmux 及其子路径，旧名目录亦然），其余路径
# 一律拒绝；删除程序/数据目录前校验目录内含 LanMux 标记文件，无标记
# 拒绝删除；删除前打印目标。
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

INSTALL_DIR="${LANMUX_INSTALL_DIR:-/opt/lanmux}"
DATA_DIR="${LANMUX_DATA_DIR:-/etc/lanmux}"
SYSTEMD_DIR="${LANMUX_SYSTEMD_DIR:-/etc/systemd/system}"

# 旧名残留（v0.9.0 改名前叫 LAN Proxy Hub）：未迁移的旧安装也一并清理。
LEGACY_INSTALL_DIR="/opt/lan-proxy-hub"
LEGACY_DATA_DIR="/etc/lan-proxy-hub"

# 旧名残留（v1.0.0 改名前叫 Fenliu）：未迁移的旧安装也一并清理。
LEGACY_FENLIU_INSTALL_DIR="/opt/fenliu"
LEGACY_FENLIU_DATA_DIR="/etc/fenliu"

NONINTERACTIVE="${LANMUX_NONINTERACTIVE:-0}"
KEEP_DATA="${LANMUX_UNINSTALL_KEEP_DATA:-1}"

log_info() { echo "[..] $*"; }
log_ok() { echo "[ OK ] $*"; }
log_warn() { echo "[WARN] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

# 允许 safe_rm_rf 删除的根（H-14）：LanMux 自己的程序/数据目录及其子路径，
# 以及改名前的旧名目录。其它一切路径一律拒绝——尤其拒绝系统目录本身
# （/、/etc、/usr、/opt、/home、/root、/var 等）与 $HOME。
# 路径覆盖变量（LANMUX_INSTALL_DIR / LANMUX_DATA_DIR）也必须落在这里面，
# 否则 validate_install_paths 在卸载开始前就拒绝（残留的测试环境变量
# + sudo -E 不得把卸载指向系统目录）。
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

validate_install_paths() {
    # validate_install_paths — 路径覆盖变量白名单校验（H-14），卸载开始前做。
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

usage() {
    echo "用法：sudo bash uninstall.sh [--non-interactive] [--help]"
    echo "  默认保留 /etc/lanmux 下的数据（重装后节点与设置还在）。"
    echo "  连数据一起删：sudo bash uninstall.sh（交互里选 2），或"
    echo "    LANMUX_NONINTERACTIVE=1 LANMUX_UNINSTALL_KEEP_DATA=0 sudo -E bash uninstall.sh"
}

main() {
    local arg=""
    for arg in "$@"; do
        case "$arg" in
            --non-interactive)
                NONINTERACTIVE=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "[ERROR] 未知参数：$arg" >&2
                usage >&2
                exit 1
                ;;
        esac
    done
    if [ ! -t 0 ] && [ "$NONINTERACTIVE" -eq 0 ]; then
        log_info "检测到非终端输入，自动切换为非交互模式（保留数据）"
        NONINTERACTIVE=1
    fi

    if [ "$(id -u)" -ne 0 ]; then
        die "请用 root 或 sudo 运行卸载脚本。"
    fi

    # 路径覆盖白名单校验（H-14）：在任何删除之前做。
    validate_install_paths

    local have_install=0
    if [ -d "$INSTALL_DIR" ] || [ -f "$SYSTEMD_DIR/lanmux-mihomo.service" ] \
        || [ -f "$SYSTEMD_DIR/lanmux-web.service" ] || [ -d "$DATA_DIR" ] \
        || [ -d "$LEGACY_INSTALL_DIR" ] || [ -d "$LEGACY_DATA_DIR" ] \
        || [ -d "$LEGACY_FENLIU_INSTALL_DIR" ] || [ -d "$LEGACY_FENLIU_DATA_DIR" ] \
        || [ -f "$SYSTEMD_DIR/hub-mihomo.service" ] \
        || [ -f "$SYSTEMD_DIR/hub-web.service" ] \
        || [ -f "$SYSTEMD_DIR/fenliu-mihomo.service" ] \
        || [ -f "$SYSTEMD_DIR/fenliu-web.service" ]; then
        have_install=1
    fi
    if [ "$have_install" -eq 0 ]; then
        echo "未检测到 LanMux 安装（$INSTALL_DIR、$DATA_DIR 与两个单元都不存在），无需卸载。"
        exit 0
    fi

    if [ "$NONINTERACTIVE" -eq 0 ]; then
        echo ""
        echo "将卸载 LanMux："
        echo "  停止并删除单元：lanmux-mihomo.service、lanmux-web.service"
        echo "  删除程序目录：$INSTALL_DIR"
        echo "  绝不改动：/etc/mihomo、mihomo 单元（旧网关）、docker"
        echo ""
        echo "数据目录 $DATA_DIR（config.yaml、lanmux.db、lanmux.env）如何处理？"
        echo "  [1] 保留数据（重装后节点与设置还在）[默认]"
        echo "  [2] 一并删除"
        local answer=""
        printf '请选择 [1/2]：'
        if ! read -r answer; then
            echo ""
            die "输入中断，卸载已取消（未做任何修改）。"
        fi
        case "$answer" in
            2)
                KEEP_DATA=0
                ;;
            *)
                KEEP_DATA=1
                ;;
        esac
    fi

    log_info "停止服务 lanmux-mihomo / lanmux-web（旧名单元一并处理）"
    systemctl stop lanmux-mihomo.service lanmux-web.service hub-mihomo.service hub-web.service fenliu-mihomo.service fenliu-web.service 2>/dev/null || true
    systemctl disable lanmux-mihomo.service lanmux-web.service hub-mihomo.service hub-web.service fenliu-mihomo.service fenliu-web.service 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/lanmux-mihomo.service" "$SYSTEMD_DIR/lanmux-web.service" \
        "$SYSTEMD_DIR/hub-mihomo.service" "$SYSTEMD_DIR/hub-web.service" \
        "$SYSTEMD_DIR/fenliu-mihomo.service" "$SYSTEMD_DIR/fenliu-web.service"
    systemctl daemon-reload 2>/dev/null || true
    log_ok "单元已删除"

    require_lanmux_marker "$INSTALL_DIR" backend bin frontend venv uninstall.sh
    safe_rm_rf "$INSTALL_DIR"
    log_ok "程序目录已删除：$INSTALL_DIR"
    if [ -d "$LEGACY_INSTALL_DIR" ]; then
        require_lanmux_marker "$LEGACY_INSTALL_DIR" backend bin frontend venv uninstall.sh
        safe_rm_rf "$LEGACY_INSTALL_DIR"
        log_ok "旧名程序目录已删除：$LEGACY_INSTALL_DIR"
    fi
    if [ -d "$LEGACY_FENLIU_INSTALL_DIR" ]; then
        require_lanmux_marker "$LEGACY_FENLIU_INSTALL_DIR" backend bin frontend venv uninstall.sh
        safe_rm_rf "$LEGACY_FENLIU_INSTALL_DIR"
        log_ok "旧名程序目录已删除：$LEGACY_FENLIU_INSTALL_DIR"
    fi

    if [ "$KEEP_DATA" -eq 1 ]; then
        log_ok "数据已保留：$DATA_DIR（重装后节点与设置都在；想彻底删除请手动 rm -rf $DATA_DIR）"
        if [ -d "$LEGACY_DATA_DIR" ]; then
            log_ok "旧名数据已保留：$LEGACY_DATA_DIR（重装时会自动迁移到 $DATA_DIR）"
        fi
        if [ -d "$LEGACY_FENLIU_DATA_DIR" ]; then
            log_ok "旧名数据已保留：$LEGACY_FENLIU_DATA_DIR（重装时会自动迁移到 $DATA_DIR）"
        fi
    else
        require_lanmux_marker "$DATA_DIR" lanmux.env lanmux.db config.yaml hub.db hub.env fenliu.db fenliu.env
        safe_rm_rf "$DATA_DIR"
        log_ok "数据已删除：$DATA_DIR"
        if [ -d "$LEGACY_DATA_DIR" ]; then
            require_lanmux_marker "$LEGACY_DATA_DIR" hub.db hub.env lanmux.db lanmux.env config.yaml
            safe_rm_rf "$LEGACY_DATA_DIR"
            log_ok "旧名数据已删除：$LEGACY_DATA_DIR"
        fi
        if [ -d "$LEGACY_FENLIU_DATA_DIR" ]; then
            require_lanmux_marker "$LEGACY_FENLIU_DATA_DIR" fenliu.db fenliu.env hub.db hub.env lanmux.db lanmux.env config.yaml
            safe_rm_rf "$LEGACY_FENLIU_DATA_DIR"
            log_ok "旧名数据已删除：$LEGACY_FENLIU_DATA_DIR"
        fi
    fi

    echo ""
    echo "LanMux 已卸载。"
    if [ "$KEEP_DATA" -eq 1 ]; then
        echo "重装命令：git clone https://github.com/moye-lab/lanmux.git && cd lanmux && sudo bash install.sh（数据会自动沿用）"
    fi
}

main "$@"
