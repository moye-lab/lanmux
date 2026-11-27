#!/usr/bin/env bash
# LanMux — 部署后一键验收。
#
# 检查项（每项打印 [PASS] / [FAIL] / [WARN] / [SKIP]，最后给汇总与退出码）：
#   1) lanmux-web /health 可达
#   2) mihomo /version 可达（带 Secret 鉴权）
#   3) SS 入口端口 TCP 能连通
#   4) Mixed 入口 HTTP 代理拉百度（应走 DIRECT，带耗时）
#   5) Mixed 入口 HTTP 代理拉 YouTube（应走代理，带耗时；未配节点时只告警）
#   6) UDP：经 Mixed SOCKS5 做一次 DNS 查询（223.5.5.5，带耗时）
#   7) 配置同步：经面板 API 查 config.in_sync（需管理员密码）
#
# 用法：bash scripts/verify.sh
#   默认测本机（127.0.0.1）；远程测：LANMUX_HOST=192.168.1.100 bash scripts/verify.sh
#   端口覆盖：LANMUX_SS_PORT / LANMUX_MIXED_PORT / LANMUX_CONTROLLER_PORT / LANMUX_WEB_PORT
#   密钥：优先用环境变量 MIHOMO_SECRET / ADMIN_PASSWORD；否则读
#   /etc/lanmux/lanmux.env（需可读；本机 root 运行默认能读）。
#   UDP 探测的目标 DNS 可覆盖：LANMUX_VERIFY_DNS_SERVER（默认 223.5.5.5）。
#
# 退出码：0 = 无 FAIL；1 = 至少一项 FAIL。WARN 不影响退出码。
#
# 注意：本脚本不用 set -e——每项检查都要跑完并报告，不能中途退出。
set -uo pipefail

LANMUX_HOST="${LANMUX_HOST:-${FENLIU_HOST:-127.0.0.1}}"
LANMUX_ENV_FILE="${LANMUX_ENV_FILE:-/etc/lanmux/lanmux.env}"
# 兼容未迁移的旧安装：新 env 文件不存在时读旧的 /etc/fenliu/fenliu.env。
if [ ! -r "$LANMUX_ENV_FILE" ] && [ -r "/etc/fenliu/fenliu.env" ]; then
    LANMUX_ENV_FILE="/etc/fenliu/fenliu.env"
fi

# 命令行环境变量优先：先快照，白名单解析后再恢复非空项。
# 每个变量都接受旧的 FENLIU_* 拼写（LANMUX_* 优先）。
_CLI_MIHOMO_SECRET="${MIHOMO_SECRET:-}"
_CLI_ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
_CLI_SS_PORT="${LANMUX_SS_PORT:-${FENLIU_SS_PORT:-}}"
_CLI_MIXED_PORT="${LANMUX_MIXED_PORT:-${FENLIU_MIXED_PORT:-}}"
_CLI_CONTROLLER_PORT="${LANMUX_CONTROLLER_PORT:-${FENLIU_CONTROLLER_PORT:-}}"
_CLI_WEB_PORT="${LANMUX_WEB_PORT:-${FENLIU_WEB_PORT:-}}"
_CLI_MIXED_USER="${LANMUX_MIXED_AUTH_USER:-${FENLIU_MIXED_AUTH_USER:-}}"
_CLI_MIXED_PASS="${LANMUX_MIXED_AUTH_PASS:-${FENLIU_MIXED_AUTH_PASS:-}}"
# ------------------------------------------------------------------ env 白名单解析
# L-25：绝不 source env 文件（内含密钥，source 会执行其中任意 shell
# 代码）。下面的三个函数是 install.sh 里 parse_env_file_value 的逐字
# 副本（保持同步）；verify.sh 独立运行，不 source 安装器。
log_warn() { echo "[WARN] $*"; }
_PARSE_WARNED_FILE=""

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

_env_first() {
    # _env_first <file> <key>... — 按顺序返回第一个非空值（用于
    # LANMUX_* / FENLIU_* 旧键名兼容）。
    local file="$1"; shift
    local k="" v=""
    for k in "$@"; do
        v="$(parse_env_file_value "$file" "$k")"
        if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
    done
    return 0
}

if [ -r "$LANMUX_ENV_FILE" ]; then
    # L-25：白名单解析逐键读取 env 文件（见上），命令行变量优先
    # （_CLI_* 快照），其次文件值；端口与 Mixed 账号同时兼容旧
    # FENLIU_* 键名。文件含无法解析的行时整个文件被拒绝（告警一次），
    # 各值回落为空，带鉴权的检查随之 SKIP。
    [ -n "${_CLI_MIHOMO_SECRET:-}" ] || [ -n "${MIHOMO_SECRET:-}" ] || MIHOMO_SECRET="$(_env_first "$LANMUX_ENV_FILE" MIHOMO_SECRET)"
    [ -n "${_CLI_ADMIN_PASSWORD:-}" ] || [ -n "${ADMIN_PASSWORD:-}" ] || ADMIN_PASSWORD="$(_env_first "$LANMUX_ENV_FILE" ADMIN_PASSWORD)"
    [ -n "${_CLI_SS_PORT:-}" ] || [ -n "${LANMUX_SS_PORT:-}" ] || LANMUX_SS_PORT="$(_env_first "$LANMUX_ENV_FILE" LANMUX_SS_PORT FENLIU_SS_PORT)"
    [ -n "${_CLI_MIXED_PORT:-}" ] || [ -n "${LANMUX_MIXED_PORT:-}" ] || LANMUX_MIXED_PORT="$(_env_first "$LANMUX_ENV_FILE" LANMUX_MIXED_PORT FENLIU_MIXED_PORT)"
    [ -n "${_CLI_CONTROLLER_PORT:-}" ] || [ -n "${LANMUX_CONTROLLER_PORT:-}" ] || LANMUX_CONTROLLER_PORT="$(_env_first "$LANMUX_ENV_FILE" LANMUX_CONTROLLER_PORT FENLIU_CONTROLLER_PORT)"
    [ -n "${_CLI_WEB_PORT:-}" ] || [ -n "${LANMUX_WEB_PORT:-}" ] || LANMUX_WEB_PORT="$(_env_first "$LANMUX_ENV_FILE" LANMUX_WEB_PORT FENLIU_WEB_PORT)"
    [ -n "${_CLI_MIXED_USER:-}" ] || [ -n "${LANMUX_MIXED_AUTH_USER:-}" ] || LANMUX_MIXED_AUTH_USER="$(_env_first "$LANMUX_ENV_FILE" LANMUX_MIXED_AUTH_USER FENLIU_MIXED_AUTH_USER)"
    [ -n "${_CLI_MIXED_PASS:-}" ] || [ -n "${LANMUX_MIXED_AUTH_PASS:-}" ] || LANMUX_MIXED_AUTH_PASS="$(_env_first "$LANMUX_ENV_FILE" LANMUX_MIXED_AUTH_PASS FENLIU_MIXED_AUTH_PASS)"
fi
MIHOMO_SECRET="${_CLI_MIHOMO_SECRET:-${MIHOMO_SECRET:-}}"
ADMIN_PASSWORD="${_CLI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-}}"
LANMUX_SS_PORT="${_CLI_SS_PORT:-${LANMUX_SS_PORT:-10001}}"
LANMUX_MIXED_PORT="${_CLI_MIXED_PORT:-${LANMUX_MIXED_PORT:-7890}}"
LANMUX_CONTROLLER_PORT="${_CLI_CONTROLLER_PORT:-${LANMUX_CONTROLLER_PORT:-9090}}"
LANMUX_WEB_PORT="${_CLI_WEB_PORT:-${LANMUX_WEB_PORT:-8086}}"
LANMUX_MIXED_AUTH_USER="${_CLI_MIXED_USER:-${LANMUX_MIXED_AUTH_USER:-}}"
LANMUX_MIXED_AUTH_PASS="${_CLI_MIXED_PASS:-${LANMUX_MIXED_AUTH_PASS:-}}"
LANMUX_VERIFY_DNS_SERVER="${LANMUX_VERIFY_DNS_SERVER:-${FENLIU_VERIFY_DNS_SERVER:-223.5.5.5}}"

N_PASS=0
N_FAIL=0
N_WARN=0
N_SKIP=0

pass() { N_PASS=$((N_PASS + 1)); echo "[PASS] $*"; }
fail() { N_FAIL=$((N_FAIL + 1)); echo "[FAIL] $*"; }
warn() { N_WARN=$((N_WARN + 1)); echo "[WARN] $*"; }
skip() { N_SKIP=$((N_SKIP + 1)); echo "[SKIP] $*"; }

# ------------------------------------------------------------------ 1/2
check_health() {
    local body=""
    body="$(curl -fsS --max-time 10 "http://${LANMUX_HOST}:${LANMUX_WEB_PORT}/health" 2>/dev/null)" || {
        fail "lanmux-web /health 不可达：http://${LANMUX_HOST}:${LANMUX_WEB_PORT}/health（面板没起来？端口对吗？）"
        return 0
    }
    if printf '%s' "$body" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
        pass "lanmux-web /health 正常：$body"
    else
        fail "lanmux-web /health 返回异常：$body"
    fi
}

check_version() {
    local args=(-fsS --max-time 10)
    if [ -n "$MIHOMO_SECRET" ]; then
        args+=(-H "Authorization: Bearer $MIHOMO_SECRET")
    fi
    local body=""
    body="$(curl "${args[@]}" "http://${LANMUX_HOST}:${LANMUX_CONTROLLER_PORT}/version" 2>/dev/null)" || {
        if [ -z "$MIHOMO_SECRET" ]; then
            fail "mihomo /version 不可达（未提供 MIHOMO_SECRET，若控制器设了 Secret 请提供后再测）"
        else
            fail "mihomo /version 不可达：http://${LANMUX_HOST}:${LANMUX_CONTROLLER_PORT}/version（mihomo 没起来？Secret 对吗？）"
        fi
        return 0
    }
    pass "mihomo /version 正常：$body"
}

# ------------------------------------------------------------------ 3
check_ss_port() {
    if (exec 3<>"/dev/tcp/${LANMUX_HOST}/${LANMUX_SS_PORT}") 2>/dev/null; then
        pass "SS 入口 TCP 能连通：${LANMUX_HOST}:${LANMUX_SS_PORT}"
    else
        fail "SS 入口 TCP 连不通：${LANMUX_HOST}:${LANMUX_SS_PORT}（mihomo 没起来或端口不对）"
    fi
}

# ------------------------------------------------------------------ 4/5
proxy_fetch() {
    # proxy_fetch <url> <label> — 经 Mixed HTTP 代理拉取，打印 "状态码 耗时"。
    local url="$1"
    local proxy="http://${LANMUX_HOST}:${LANMUX_MIXED_PORT}"
    if [ -n "$LANMUX_MIXED_AUTH_USER" ]; then
        proxy="http://${LANMUX_MIXED_AUTH_USER}:${LANMUX_MIXED_AUTH_PASS}@${LANMUX_HOST}:${LANMUX_MIXED_PORT}"
    fi
    curl -fsS -x "$proxy" --max-time 20 -o /dev/null -w '%{http_code} %{time_total}' "$url" 2>/dev/null
}

check_proxied_fetch() {
    local out=""
    local code=""
    local secs=""
    out="$(proxy_fetch "https://www.baidu.com" "baidu")"
    if [ -n "$out" ]; then
        code="${out%% *}"
        secs="${out##* }"
        case "$code" in
            2*|3*)
                pass "Mixed 代理拉百度成功（DIRECT，HTTP $code，${secs}s）"
                ;;
            *)
                fail "Mixed 代理拉百度返回 HTTP $code（${secs}s）"
                ;;
        esac
    else
        fail "Mixed 代理拉百度失败（DIRECT 应通：mihomo 没起来？DNS 卡住？）"
    fi
}

# ------------------------------------------------------------------ API 探测
# 一次 python3 调用完成：登录 → 诊断状态 → 节点数。
# 输出 KEY=value 行：LOGIN_OK / IN_SYNC / MIHOMO_RUNNING / ENABLED_NODES。
lanmux_api_probe() {
    python3 - "$LANMUX_HOST" "$LANMUX_WEB_PORT" "$ADMIN_PASSWORD" <<'PYEOF'
import json
import sys
import urllib.error
import urllib.request

host, port, password = sys.argv[1], sys.argv[2], sys.argv[3]
base = "http://%s:%s" % (host, port)


def call(method, path, token=None, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}
    except Exception:
        return None, {}


status, login = call("POST", "/api/auth/login", payload={"password": password})
if status != 200 or not login.get("token"):
    print("LOGIN_OK=0")
    sys.exit(0)
print("LOGIN_OK=1")
token = login["token"]
status, diag = call("GET", "/api/diagnostics/status", token=token)
if status == 200:
    print("MIHOMO_RUNNING=%s" % (1 if diag.get("mihomo", {}).get("running") else 0))
    print("IN_SYNC=%s" % (1 if diag.get("config", {}).get("in_sync") else 0))
    print("CONFIG_EXISTS=%s" % (1 if diag.get("config", {}).get("exists") else 0))
    print("LAST_APPLY_ERROR=%s" % (diag.get("config", {}).get("last_apply_error") or ""))
else:
    print("MIHOMO_RUNNING=0")
    print("IN_SYNC=0")
    print("CONFIG_EXISTS=0")
    print("LAST_APPLY_ERROR=")
status, nodes = call("GET", "/api/nodes", token=token)
if status == 200 and isinstance(nodes, list):
    print("ENABLED_NODES=%d" % sum(1 for n in nodes if n.get("enabled")))
else:
    print("ENABLED_NODES=-1")
PYEOF
}

check_youtube_and_sync() {
    local probe_login_ok=0
    local probe_in_sync=0
    local probe_mihomo_running=0
    local probe_enabled_nodes=-1
    local probe_last_error=""
    if [ -n "$ADMIN_PASSWORD" ] && command -v python3 >/dev/null 2>&1; then
        local key=""
        local value=""
        while IFS='=' read -r key value; do
            case "$key" in
                LOGIN_OK) probe_login_ok="$value" ;;
                IN_SYNC) probe_in_sync="$value" ;;
                MIHOMO_RUNNING) probe_mihomo_running="$value" ;;
                ENABLED_NODES) probe_enabled_nodes="$value" ;;
                LAST_APPLY_ERROR) probe_last_error="$value" ;;
            esac
        done <<EOF_PROBE
$(lanmux_api_probe)
EOF_PROBE
    fi

    # 5) YouTube 代理探测：有启用节点时失败算 FAIL，否则只 WARN。
    local out=""
    local code=""
    local secs=""
    out="$(proxy_fetch "https://www.youtube.com" "youtube")"
    if [ -n "$out" ]; then
        code="${out%% *}"
        secs="${out##* }"
        case "$code" in
            2*|3*)
                pass "Mixed 代理拉 YouTube 成功（代理，HTTP $code，${secs}s）"
                ;;
            *)
                if [ "$probe_enabled_nodes" -gt 0 ] 2>/dev/null; then
                    fail "Mixed 代理拉 YouTube 返回 HTTP $code（${secs}s，已配 ${probe_enabled_nodes} 个启用节点，应能通）"
                else
                    warn "Mixed 代理拉 YouTube 返回 HTTP $code（${secs}s；未配节点时属预期，先在面板里加节点再测）"
                fi
                ;;
        esac
    else
        if [ "$probe_enabled_nodes" -gt 0 ] 2>/dev/null; then
            fail "Mixed 代理拉 YouTube 失败（已配 ${probe_enabled_nodes} 个启用节点：节点挂了？分流规则有误？）"
        else
            warn "Mixed 代理拉 YouTube 失败（未配节点或查不到节点数时属预期，先在面板里加节点再测）"
        fi
    fi

    # 7) 配置同步。
    if [ -z "$ADMIN_PASSWORD" ]; then
        skip "配置同步检查：未提供 ADMIN_PASSWORD（本机 root 运行可自动读 lanmux.env）"
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        skip "配置同步检查：无 python3"
        return 0
    fi
    if [ "$probe_login_ok" != "1" ]; then
        skip "配置同步检查：面板登录失败（ADMIN_PASSWORD 不对？）"
        return 0
    fi
    if [ "$probe_mihomo_running" != "1" ]; then
        fail "配置同步检查：面板报 mihomo 未运行"
        return 0
    fi
    if [ "$probe_in_sync" = "1" ]; then
        pass "配置同步：线上配置与面板一致（in_sync=true）"
    else
        fail "配置同步：线上配置与面板不一致（in_sync=false；最近错误：${probe_last_error:-未知}）"
    fi
}

# ------------------------------------------------------------------ 6 UDP
# 经 Mixed SOCKS5 做 UDP ASSOCIATE，向目标 DNS 发一次 A 查询。
# 成功 = 收到 Transaction ID 一致的 DNS 应答。
socks5_udp_dns_check() {
    if ! command -v python3 >/dev/null 2>&1; then
        skip "UDP 检查：无 python3"
        return 0
    fi
    local out=""
    out="$(python3 - "$LANMUX_HOST" "$LANMUX_MIXED_PORT" "$LANMUX_VERIFY_DNS_SERVER" \
        "$LANMUX_MIXED_AUTH_USER" "$LANMUX_MIXED_AUTH_PASS" <<'PYEOF'
import socket
import struct
import sys
import time

proxy_host, proxy_port = sys.argv[1], int(sys.argv[2])
dns_server = sys.argv[3]
username = sys.argv[4] if len(sys.argv) > 4 else ""
password = sys.argv[5] if len(sys.argv) > 5 else ""


def fail(msg):
    print("FAIL " + msg)
    sys.exit(1)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            fail("proxy closed the connection")
        buf += chunk
    return buf


try:
    tcp = socket.create_connection((proxy_host, proxy_port), timeout=10)
except OSError as exc:
    fail("cannot connect to mixed port: %s" % exc)
try:
    tcp.sendall(b"\x05\x01\x02" if username else b"\x05\x01\x00")
    ver, method = recv_exact(tcp, 2)
    if ver != 5:
        fail("not a SOCKS5 proxy")
    if method == 2:
        user = username.encode()
        pw = password.encode()
        tcp.sendall(
            b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw
        )
        _, status = recv_exact(tcp, 2)
        if status != 0:
            fail("SOCKS5 username/password auth rejected")
    elif method != 0:
        fail("no acceptable SOCKS5 auth method")
    # UDP ASSOCIATE for 0.0.0.0:0.
    tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    head = recv_exact(tcp, 4)
    if head[1] != 0:
        fail("UDP ASSOCIATE rejected (reply %d)" % head[1])
    atyp = head[3]
    if atyp == 1:
        relay = socket.inet_ntoa(recv_exact(tcp, 4))
    elif atyp == 3:
        n = recv_exact(tcp, 1)[0]
        relay = recv_exact(tcp, n).decode()
    elif atyp == 4:
        relay = socket.inet_ntop(socket.AF_INET6, recv_exact(tcp, 16))
    else:
        fail("unexpected relay address type %d" % atyp)
    relay_port = struct.unpack(">H", recv_exact(tcp, 2))[0]
    if relay in ("0.0.0.0", "::"):
        relay = proxy_host
    # Minimal DNS query: A www.baidu.com (domestic host, AliDNS answers).
    import random

    tid = random.randint(0, 65535)
    qname = b"".join(
        bytes([len(p)]) + p.encode() for p in "www.baidu.com".split(".")
    ) + b"\x00"
    query = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + qname
    query += struct.pack(">HH", 1, 1)
    packet = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(dns_server)
        + struct.pack(">H", 53)
        + query
    )
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(10)
    start = time.monotonic()
    udp.sendto(packet, (relay, relay_port))
    data, _ = udp.recvfrom(2048)
    elapsed = time.monotonic() - start
    if len(data) < 12 or data[3] not in (1, 3, 4):
        fail("bad SOCKS5 UDP reply")
    header_len = {1: 10, 3: 7 + data[4], 4: 22}[data[3]]
    dns = data[header_len:]
    if len(dns) < 12:
        fail("short DNS reply")
    resp_tid, flags = struct.unpack(">HH", dns[:4])
    if resp_tid != tid:
        fail("DNS transaction ID mismatch")
    if not flags & 0x8000:
        fail("DNS reply is not a response")
    print("OK %.2fs" % elapsed)
except SystemExit:
    raise
except (OSError, ValueError, KeyError, struct.error) as exc:
    fail(str(exc))
PYEOF
)"
    case "$out" in
        OK*)
            pass "UDP 检查：经 SOCKS5 向 ${LANMUX_VERIFY_DNS_SERVER} 查 www.baidu.com 成功（${out#OK }）"
            ;;
        *)
            warn "UDP 检查失败：${out#FAIL }（可能是上游 DNS 不通或 UDP 被拦；TCP 代理不受影响）"
            ;;
    esac
}

# ------------------------------------------------------------------ 主流程
echo "LanMux 验收 — 目标 ${LANMUX_HOST}（面板 ${LANMUX_WEB_PORT} / 控制器 ${LANMUX_CONTROLLER_PORT} / SS ${LANMUX_SS_PORT} / Mixed ${LANMUX_MIXED_PORT}）"
echo ""
check_health
check_version
check_ss_port
check_proxied_fetch
check_youtube_and_sync
socks5_udp_dns_check
echo ""
echo "汇总：PASS ${N_PASS} / FAIL ${N_FAIL} / WARN ${N_WARN} / SKIP ${N_SKIP}"
if [ "$N_FAIL" -gt 0 ]; then
    echo "验收未通过：有 ${N_FAIL} 项 FAIL，见上方说明。"
    exit 1
fi
echo "验收通过。"
exit 0
