# 更新记录

LanMux 的版本更新记录（新版本在前）。

## v1.0.2（2026-11-27 发布）

修复 v1.0.1 的面板白屏回归（不加功能、不改结构）。

* 前端：v1.0.1 加固时“待重启 Mihomo”横幅缺两个 `</div>`，整个 `<main>` 内容区（6 个标签页 + 全部横幅）被吞进 `display: none` 的横幅里，面板只剩顶栏和底导航。补上两个闭合标签；另修 `loadAll()` 全量成功时不清旧错误提示的问题（首次登录后会顶着一条“登录已过期”的错误横幅）。
* 文档：README 的 docker run 命令补 `--user 0:0`——从 v1.0.0（全 root 运行）升级时旧数据卷是 root 属主，缺它容器会因 `/data` 不可写而重启循环；入口脚本以 root 修正卷属主后降权到 lanmux 用户。
* 回归防护：jsdom 测不到 `display: none` 导致的白屏（无布局、textContent 含隐藏子树），后续以前端 div 平衡检查 + 真浏览器冒烟为准。

## v1.0.1（2026-11-26 发布）

安全加固补丁（不加功能、不改结构、不改端口与用户操作逻辑）。全面代码审查发现 111 项已确认问题（高 15 / 中 51 / 低 45），本次全部修复；另修复 §4 潜在风险中的 PR-34/PR-40/PR-11 与设计项 D-04/D-07。审查报告与修复报告见仓库外文档（不随源码发布）。

* 认证：登录失败锁定（IP + 账号双维度，5 次失败锁 15 分钟、指数退避至 120 分钟，429 + Retry-After）；首次 setup 改为一次性 setup token（启动日志打印，仅存内存，setup 完成后失效、端点永久 403）；Token 改 HttpOnly Cookie + CSP 安全头，支持滑动轮换与注销全部会话；`LANMUX_SETUP_LOOPBACK_ONLY=1` 可切换 setup 仅 loopback（默认关）。
* 配置应用与回滚：`apply()` 加进程锁 + 原子写（唯一后缀临时文件 → fsync → os.replace）+ 修订号 DB 原子自增（只在成功后递增）；回滚前校验 `.bak` 合法性，缺失/损坏时拒绝回滚且绝不删 live 文件，保留 5 代备份；热加载捕获全部异常走回滚；单次快照读库；持久化失败记日志 + 置 drift。
* Secret/端口修改自锁修复：真实 mihomo v1.19.34 已证实 Secret 与监听端口均不可热重载，改为重启流程（写盘 + 置 `restart_pending` + 明确告知用户重启，失败时 DB 与磁盘同时回滚），新增 `POST /api/diagnostics/confirm-restart` 做重载后确认。
* 静默 DIRECT 改为 fail-closed：绑定组节点全部禁用/删除后生成 REJECT（不再静默变 DIRECT）+ 面板强警告 + 漂移标记；Default 未绑定时拒绝应用并给出指引；DNS fallback 在 Default 无 live 节点时整段省略；节点删除保留悬空绑定（同样 REJECT）。
* 下载链完整性：新增 `scripts/asset-checksums.sha256` 信任根，install.sh 与 Dockerfile 强制 `sha256sum -c`，不匹配即中止；基础镜像钉 digest；geodata 内容用哈希钉死。
* 节点解析与导入：共享 `validate_proxy_dict()` 严格校验（type 白名单、端口 1–65535、UUID/cipher 格式），PUT 非法节点返回 400 拒绝入库；去重在最终名称集合中循环校验；VMess `tls: true` 真启用 TLS；批量导入去重 + 500 行上限 + 错误行号与脱敏回显；坏 `proxy_json` 单行容错。
* 脱敏：`masking.py` 白名单递归脱敏，补全 `obfs-password` / `public-key` / `short-id`；节点默认脱敏，唯一明文路径为 `GET /api/nodes/{id}/export`（审计日志）；Mixed 用户名/密码成对校验。
* 规则/诊断/DNS：自定义规则三方共用校验；探针并发上限 2、去重、每 IP 60/min、总 deadline；出口 IP 回显 64KB 上限；诊断错误类别码；fallback-filter 补 `ipcidr` / `domain`；nameserver 改 `https://dns.google/dns-query`。
* 数据库与设置：绑定单事务 + 部分唯一索引；settings 全校验后单事务提交；WAL + busy_timeout；启动完整性检查 + 自动恢复；`Database.backup()` 在线备份（0600、留 7 个、日备）；`get_settings()` 坏值容错。
* 容器与 systemd 脱离 root：Dockerfile 增加 `lanmux` 用户（10001）+ `USER lanmux`，entrypoint 先修正卷属主再降权；两个 systemd 单元加 `User=lanmux` / `Group=lanmux` + 沙箱收敛（NoNewPrivileges、ProtectSystem、PrivateTmp、CapabilityBoundingSet）；端口与 host 网络不变。
* 文件权限：DB 0600 预建 + 启动收敛 0600/0700；`lanmux.env` 在 `umask 077` 子 shell 内写；备份只含 db + config.yaml。
* 安装/卸载：`safe_rm_rf` 白名单（拒绝 `/`、`/etc`、`/usr`、`/opt`、`/home`、`/root` 等系统目录）；`source` 改白名单解析器；密码走 0600 文件；`LANMUX_FRESH_INSTALL=1` 需 `LANMUX_FRESH_INSTALL_CONFIRM=1` + 清空前自动备份。
* 供应链/CI：pip-tools 真 lockfile + `--generate-hashes`（pip-audit 0 漏洞）；CI 双推 GHCR + Docker Hub；Alpine 3.24.4@digest；14 个 `uses:` 钉 commit SHA；provenance + SBOM + Trivy + cosign；Tailwind 改本地编译。
* 前端：12 个写操作入口检查 `reload.ok`；持久错误横幅；写与刷新解耦；loadAll 逐项容错；表单校验对齐后端；50 条分页；错误分级。
* 测试：后端 229 → 497 passed，前端 jsdom v097 109/109、v098 70/70，shell 套件 101/101 + 20/20；两处把旧行为钉死为期望的测试已改成断言新行为。

已知残余风险（需真机验证）：Secret/端口重启流程、非 root 容器冷启动、install.sh/uninstall.sh 端到端、CI 首次真实运行、下载链哈希直连环境复核；§4 潜在风险 40 项与 §5 需验证 37 项未修（未经验证，按任务书不修）。

## v1.0.0（2026-11-26 发布）

2026-11-25 内部标识统一（Fenliu/HUB → LanMux），2026-11-26 发布前整改后发布。

内部标识统一为 LanMux。

* 统一项目内部命名。
* 统一安装目录与运行目录。
* 统一环境变量主名称为 LANMUX_*。
* 统一数据库文件名为 lanmux.db。
* 统一 systemd 服务名称。
* 统一 Docker 容器与镜像名称。
* 支持三级环境变量兼容：LANMUX_*、FENLIU_*、HUB_*。
* 支持旧 Fenliu 与 LAN Proxy Hub 安装自动迁移。
* 支持旧 Docker 数据文件迁移。
* 保留旧前端 localStorage 登录与偏好兼容。
* 修正旧仓库地址引用。

发布前整改（2026-11-26）：

* Docker 正式镜像：`docker-compose.yml` 默认拉预构建镜像（`docker compose pull && docker compose up -d`），源码构建移到 `docker-compose.dev.yml`；一条 `docker run` 命令也可直接启动（推荐，免克隆）。
* 配置状态模型：面板与 API 明确区分已保存 / 已生成 / 已校验 / 已应用 / 运行中五态，显示库修订（DB Revision）与运行修订（Running Revision）。
* 配置 Revision 与漂移（DRIFT）：每次生成配置递增修订号；应用失败时运行配置保持最后成功版本、数据库变更保留，状态显示 DRIFT，可一键重新应用。
* 版本信息：构建时把 Git Commit 与构建时间打进镜像；`GET /health` 与 `GET /api/version` 返回 version / commit / build_time / mihomo_version，设置页有版本信息卡片；侧边栏品牌改为动态取版本（取不到时回退 v1.0.0）。
* 节点健康：显示可达性、延迟、上次探测、失败次数、连续失败次数与失败原因，并提示“测速结果仅代表探测时状态，不等同于真实业务带宽和长期稳定性”。
* 路由诊断：显示连接状态（已连接 / 直连 / 不可达 / 未知）与节点选择策略；新增手动“探测出口 IP”按钮（可选诊断，不自动探测，拿不到报不可用，不伪造）。
* 回退行为写死：组里一个节点都没配 → 编译成 DIRECT；组里有节点但全部不可达 → 连接失败，不静默转 DIRECT。
* README 产品化：第一屏收紧，安装路径 Docker（推荐）在前，故障排查七步重写，Host Network 安全提示挪到安装命令旁，新增 5 张界面截图。
* 默认面板端口由 8080 改为 8086（8080 太热门易冲突），Docker 与 systemd 共用同一套默认端口 8086/10001/7890/9090。

## v0.9.9（2026-11-25，修复 v0.9.8 安装器缺失 systemd 单元模板）

- v0.9.7 合仓时漏拷了 `systemd/`（Docker 分仓早先删过自己的旧单元
  文件），v0.9.8 的安装器在安装单元那步报错退出（RN 实测发现）；
  本版补回 `fenliu-mihomo.service` / `fenliu-web.service`（与主线
  逐字节一致），安装器缺模板时给明确报错不再是裸 `sed` 报错，另补
  仓库布局回归测试（`test_repo_layout.py`，2 项）。
- 注意：v0.9.8（`eea7bce`）的安装器是坏的，不要用它安装；从
  v0.9.9 起安装。

## v0.9.8（2026-11-25，Docker 健康检查 + 资源刷新 + CI smoke test）

- All-in-One 容器新增 `HEALTHCHECK`（`backend/app/healthcheck.py`）：
  同时检查 LanMux Web `/health` 与 Mihomo 控制器 `/version`（控制器
  需鉴权，healthcheck 从数据库读 Mihomo Secret），任一失联即
  unhealthy；启动宽限从 15 秒放宽到 30 秒。健康检查逻辑已用真实
  面板 + 模拟控制器验证三种状态（都正常 / mihomo 挂 / Web 挂）。
- 新增 `HUB_REFRESH_ASSETS=1`（默认 0）：镜像升级后显式设置一次，
  启动时刷新 `/data` 里的 GeoIP/GeoSite/Country.mmdb 与 metacubexd；
  默认仍不覆盖持久化数据。注意刷新会替换自定义过的 metacubexd UI。
- CI 增加 amd64 冷启动 smoke test：构建镜像后跑容器、等 Docker
  健康状态为 healthy 才放行多架构推送（`docker` 任务现依赖
  `test` 与 `docker-smoke`）；真实运行须由 GitHub Actions 完成，
  本地沙箱无 Docker 守护进程、未伪造该结果。
- supervisor 崩溃恢复（任务书 P0-2）本次未动代码，仍待 N1 真机
  杀进程实测；CI 前端测试、配置状态模型等其余 v1.0 准备项未做。

## v0.9.7（2026-11-25，合仓：systemd 与 Docker 同仓）

- systemd 原生安装器与 Docker 单镜像 All-in-One 合入同一仓库
  `sg/lanmux-unified`；原两仓 `sg/lanmux` 与
  `sg/lan-proxy-hub-docker` 不动，Docker 分仓归档停更。
- 环境变量统一读法：`FENLIU_*` 优先，`HUB_*` 兼容（`main.py` 与
  `init_fenliu` 均已接别名），旧 Docker `.env` 不用改；新增 5 个
  回归测试钉死别名行为。
- 种子助手合一：`init_hub.py` 删除，`init_fenliu.py` 承接
  `--auto-secrets`（容器零秘密冷启动）与分组迁移；`docker_runner`
  改调 `init_fenliu`。
- 主线多容器 Docker 备选（`backend/Dockerfile` +
  `backend/docker-entrypoint.sh`）删除，只留 N1 冷启动验证过的
  all-in-one；Docker 章节与目录树按合仓后布局重写。

## v0.9.6（2026-11-24，30 项审计修复）

- 回滚报告误报修正（`config_service._rollback`）：文件恢复与热加载
  分开报告；mihomo 停机时文件已恢复、热加载失败，接口返回
  `rolled_back: true` 并说明恢复后的配置待 mihomo 重启后生效，
  不再误报“rollback also failed”。回归测试更新。
- README 两处过期数字修正：AI 组“11 个域名”→ 9 个；健康检查
  “interval 300，timeout 5”→ interval 60、timeout 5000。
- 卸载完成后的重装提示改指 git 克隆路径（原先指向刚被删掉的
  `/opt/fenliu`）；link-check 的 User-Agent 改名
  `lanmux-link-check`；端口表补充 Mixed 口默认无鉴权的说明。

## v0.9.5（2026-11-24，前端依赖本地化）

- Alpine.js 3.14.8 与 Tailwind Play CDN 3.4.17 打包进
  `frontend/vendor/`，面板不再依赖任何外网 CDN，修电脑上打开
  面板一片空白（jsdelivr 被连接重置）；install.sh 改为拷贝整个
  `frontend/` 目录；补 3 个回归测试。

## v0.9.4（2026-11-24，登录死锁修复）

- `get_db` 不再是持有 RLock 的 yield 依赖，锁下移到 Database
  每个方法内部，修登录并发触发的跨线程释锁死锁；补 4 个回归测试。

## v0.9.3（2026-11-24，运行时主备切换修复）

- 健康检查 timeout 单位是毫秒：分组 timeout 5（5ms）→ 5000，
  interval 60，lazy 关闭；修主节点故障时 fallback 永不切换的问题。
  RN 封堵复测：封 Hy2 后 21 秒切 VLESS，解封 10 秒切回。

## v0.9.2（2026-11-24，产品化加固第一批）

- 新增路由诊断（`POST /api/diagnostics/route-check`，诊断页"路由
  诊断"卡片）：输入域名，按配置编译的真实规则顺序匹配，展示命中
  规则 → 分组 → 策略 → 当前出口节点 → 延迟；当前节点优先取 Mihomo
  实时状态，Mihomo 不可达时按探活状态推算；未命中域名规则时如实
  说明后续走向（GEOIP CN → DIRECT，否则 Default 组）。
- 节点失效原因：测速失败时把脱敏后的一行原因存入 nodes 表新列
  `last_error`（老库自动迁移补列），成功时清空；节点列表离线时在
  状态旁显示原因。
- 文档：首屏说明"LanMux 不是什么"，新增"客户端配置"与"安全说明"
  章节；Docker 分仓 `sg/lan-proxy-hub-docker` 停在 v0.6.0、暂缓同步。

## v0.9.1（2026-11-24，品牌改名：Fenliu → LanMux）

- 项目品牌改名 LanMux（副标题：多节点聚合智能分流系统）：仓库
  `sg/lanmux`，面板标题与登录/向导/侧边栏品牌均为 LanMux，SS 总节点
  默认名 `LanMux-Core`，容器/镜像名 `lanmux`。本版只改品牌名、功能
  零变化；内部标识保持不变（安装路径 `/opt/fenliu` 与 `/etc/fenliu`、
  单元 `fenliu-web`/`fenliu-mihomo`、环境变量 `FENLIU_*`、数据文件
  `fenliu.db`/`fenliu.env`），旧安装重跑安装命令即升级（数据、节点、
  密码全部保留）。全部 API 与测试向后兼容。

## v0.9.0（2026-11-24，改名：LAN Proxy Hub → Fenliu）

- 项目改名 Fenliu（分流的拼音）：仓库 `sg/fenliu`，安装路径
  `/opt/fenliu` 与 `/etc/fenliu`，数据文件 `fenliu.db`/`fenliu.env`，
  单元 `fenliu-web`/`fenliu-mihomo`，环境变量 `HUB_*` →
  `FENLIU_*`（如 `FENLIU_WEB_PORT`），面板标题与 SS 总节点名均为
  Fenliu。功能零变化，全部 API 与测试向后兼容。
- 升级自动迁移（`install.sh` 的 `migrate_legacy_install`，幂等）：
  检测到旧名安装时，停旧服务、数据目录整体搬家、内部文件改名、
  env 文件键名与路径值改写、DB 里 `external_ui` 指向新 ui 路径、
  旧单元与旧程序目录删除；节点、规则、设置、密码全部保留。交互
  取消时不做任何修改；新旧数据目录并存时跳过迁移并提示手动处理。
- 卸载脚本同步清理旧名残留（旧单元、旧程序目录；数据按保留/删除
  选项一并处理）。后端 144 个测试全过，界面 102/102 全过。

## v0.8.1（2026-11-24，修刷新 404）

- 现象：在分流页（URL 带 `#routing` 后缀）点刷新，页面变成
  `{"detail":"Not Found"}`。根因不在面板代码：RN 访问日志实锤，刷新
  请求到服务端时已变成 `GET /%23routing`——用户手机网络链路上的某个
  中转（请求来自 Google 云 IP，疑似 iCloud Private Relay 或代理/VPN
  出口）把 `#` 编码成了 `%23`，StaticFiles 找不到该文件而 404。
- 修法：后端去掉 StaticFiles 挂载，改显式路由 + SPA 兜底——`/` 返回
  面板页，未知非 API 路径（`/%23routing`、`/routing` 等）也返回面板页，
  真实静态文件仍直接 served，路径穿越被 `resolve` +
  `is_relative_to` 挡住；未知 `/api/*` 路径仍返回 JSON 404。
- 前端 `applyHash` 增强：无有效 hash 时从 pathname 恢复标签页
  （`/%23routing` 或 `/routing` 都回到分流页），`switchTab` 顺手把地址
  栏改回 `#routing`。后端 144 个测试全过，界面 102/102 全过。

## v0.8.0（2026-11-24，分流组扩展：5 组 → 14 组，分组名称全部英文）

- 新增 9 个分流组：Netflix（从 Streaming 独立）、TikTok、Spotify、
  Twitter、Facebook、Google、Apple、Microsoft、Bilibili；Streaming
  保留 Disney+ / HBO / Hulu / Prime Video。规则按
  YouTube → Telegram → Netflix → TikTok → Spotify → Twitter →
  Facebook → Streaming → AI → Google → Apple → Microsoft →
  Bilibili → Default 顺序首次匹配，AI 域名组始终在 Google 组之前
  （gemini.google.com 等是 google.com 子域名）。
- 分组名称全部改为英文：流媒体 → Streaming、AI 服务 → AI、默认代理
  → Default（含 mihomo 策略组名与 DNS fallback `#Default`）。
- 升级迁移（`init_fenliu`，幂等）：空的代理组自动继承默认组的绑定
  （新组升级后立即可用，不会直连）；已绑定组绝不覆盖；Apple /
  Microsoft / Bilibili 三组刻意不继承，保持直连；自定义规则里旧中文
  目标（流媒体 / AI 服务 / 默认代理）自动改名为英文。
- 前端：分流卡片 14 张、初始 `groupDrafts` 补齐 14 组（缺它会在启动时
  报 Alpine 表达式错误）、自定义规则目标下拉 14 个英文名 + DIRECT /
  REJECT。后端 139 个测试全过，界面 96/96 全过。

## v0.7.7（2026-11-24，界面舒适度优化与小修）

- 面板（视觉，只加不改结构）：全站 10/11px 小字上调 1px；启停开关 28×16 放大为 40×22 并扩大点击热区、关闭态加描边；勾选框跟随主题色；手机上输入框用 16px 避免 iOS 聚焦自动放大；触屏设备上按钮 / 输入框最小高度约 34 / 40px；键盘焦点可见；顶部加一层随主题的柔和渐变光晕；尊重「减少动态效果」系统设置。
- 面板（布局）：桌面侧边栏改为吸附定位（长页面滚动时导航不再被带走）；Toast 在手机上居中并避开底部 Dock，桌面仍在右下；主内容底部留白加大。
- 面板（小修）：延迟 >250ms 用橙色徽章，与「离线」红色区分；`api()` 对 FastAPI 422 的数组型 `detail` 不再显示 `[object Object]`；状态轮询失败时顶栏出现「状态获取失败」提示（原先静默）；保存设置时若热重载失败，提示改为报错而非「已保存并重载」；标签页切回前台时立即补一次状态；去掉写死的 indigo 色，改用主题变量。
- 不变：单文件无构建、Alpine 3.14.8、离线二维码库、全部后端接口（含 v0.5.0 的批量操作与重新应用）。后端仅版本号升至 0.7.7。

## v0.7.6（2026-11-24，Claude 控制台版功能合入）

- 面板：挑入 Claude 版（sg/lan-proxy-hub-claude）的 5 项功能——① Hash
  路由：当前标签页反映在 URL（#nodes 等），刷新与浏览器前进/后退保持
  标签；② 分流卡片新增「按延迟自动填充」：延迟最低的在线节点作主，
  其余在线节点按延迟作备用；③ 删节点影响提示：主线已有
  （nodeReferences），本版确认保留；④ 批量导入失败行留在输入框，改完
  直接重试（行号为原始文本行号）；⑤ 配置预览 YAML 语法着色（键/注释/
  字符串/数字/布尔分色）。界面保持 Zashboard 风格不变，后端接口未变。

## v0.7.5（2026-11-24，登录提速）

- 面板：登录后的数据加载由串行改并行——设置/节点/绑定/自定义规则/
  SS 链接 5 个请求 Promise.all 一起发，不再一个一个等往返；状态刷新
  （mihomo /traffic 采样要等下一个 1 秒 tick）改后台加载，面板先出来、
  KPI 数值随后补齐。手机上登录到进面板约从 6-7 秒降到 2 秒。
  仍为单文件无构建前端，向后兼容全部既有 API。
- 后端未动（仅版本号升至 0.7.5）；v0.5.0 的后端接口（批量操作、重新应用）
  与 v0.4.1–v0.4.4 的修复全部保留。

## v0.7.4（2026-11-24，KPI 卡片紧凑化）

- 面板：总览 4 张 KPI 卡片同步收紧——内边距 p-3→p-2.5、数值字号
  text-base→text-sm、行间距 mt-1.5/mt-1→mt-1/mt-0.5、进度条 h-1.5→h-1、
  状态图标 w-6→w-5、网格间距 gap-2.5→gap-2；卡片高度约减 15%，
  其它卡片不受影响。仍为单文件无构建前端，向后兼容全部既有 API。
- 后端未动（仅版本号升至 0.7.4）；v0.5.0 的后端接口（批量操作、重新应用）
  与 v0.4.1–v0.4.4 的修复全部保留。

## v0.7.3（2026-11-24，底部导航悬浮胶囊化）

- 面板：移动端底部导航由通栏改成悬浮胶囊卡片——左右边距与顶栏
  卡片一致（inset-x-2.5）、四边完整边框 + rounded-2xl 圆角、底部
  留白取 max(10px, 刘海屏安全区），不再用安全区做内边距。仍为单文件
  无构建前端，向后兼容全部既有 API。
- 后端未动（仅版本号升至 0.7.3）；v0.5.0 的后端接口（批量操作、重新应用）
  与 v0.4.1–v0.4.4 的修复全部保留。

## v0.7.2（2026-11-24，顶部状态栏悬浮卡片化）

- 面板：顶部状态栏由通栏改为悬浮卡片——左右/顶部边距与下方内容
  卡片对齐（mx/mt 与 main 的 p-2.5/sm:p-4/lg:p-5 一致）、四边完整
  边框 + rounded-2xl 圆角、吸顶时顶部留空隙（top-2.5/sm:top-4/lg:top-5）。
  仍为单文件无构建前端，向后兼容全部既有 API。
- 后端未动（仅版本号升至 0.7.2）；v0.5.0 的后端接口（批量操作、重新应用）
  与 v0.4.1–v0.4.4 的修复全部保留。

## v0.7.1（2026-11-24，移动端横向溢出修复）

- 面板：修移动端页面横向溢出（body 与主容器加 overflow 截断、网格
  子项加 min-width: 0、各区网格显式单列默认、二维码行改
  minmax(0,1fr)）；波形图下方的"开启自动轮询"死提示改成可点按钮，
  一点即开 5s 自动采样。仍为单文件无构建前端，向后兼容全部既有 API。
- 后端未动（仅版本号升至 0.7.1）；v0.5.0 的后端接口（批量操作、重新应用）
  与 v0.4.1–v0.4.4 的修复全部保留。

## v0.7.0（2026-11-24，Zashboard 风格界面重构）

- 面板：6 套主题预设（暗夜/纯净/Dracula/Nord/Sunset/翡翠，本地 CSS
  实现、无新增外部依赖）、可折叠桌面侧栏、移动端毛玻璃悬浮底栏
  （6 格全覆盖）、纯内联 SVG 实时吞吐速率波形图（接真实流量数据）、
  节点管理卡片网格/列表双视图切换、业务分流点击式节点矩阵（★ 设主、
  点卡片增删有序备用，保存时主备自动去重）；总节点二维码、出站节点
  网格、批量操作、重新应用全部保留。仍为单文件无构建前端，向后兼容
  全部既有 API。
- 后端未动（仅版本号升至 0.7.0）；v0.5.0 的后端接口（批量操作、重新应用）
  与 v0.4.1–v0.4.4 的修复全部保留。

## v0.5.1（2026-11-24，移动端紧凑布局优化）

- 面板：移动端 KPI 2×2 网格、总节点二维码（二维码库 vendored 进页面、
  无外网也可生成、可下载 SVG）、出站节点速览条、业务分流备用节点
  点击增删标签流、6 格统一 SVG 底部导航（含设置）、链路诊断并排卡片；
  桌面端同步紧凑化。仍为单文件无构建前端，向后兼容全部既有 API。
- v0.5.0 的后端接口（批量操作、重新应用）与 v0.4.1–v0.4.4 的修复全部保留。

## v0.5.0（2026-11-24，控制台 UI 全面重构）

- 面板：全面重构为专业控制台（侧边导航 + 顶部状态栏 + 深浅色主题
  + KPI 工作台 + 节点筛选/排序/批量启停删/URI 导出/隐私脱敏 +
  业务分流延迟感知与批量保存 + 配置漂移一键重新应用 + 深色终端
  配置预览）；仍为单文件无构建前端，向后兼容全部既有 API。
- 后端：新增 `POST /api/nodes/batch-action`（批量启/停/删，一次重载）
  与 `POST /api/diagnostics/reapply`（手动重新编译并热重载配置）。
- v0.4.1–v0.4.4 的修复全部保留（绑定保存按钮 `!!`、groupDrafts
  预填、client-fingerprint、升级保留 fenliu.env 密码）。

## v0.4.4（2026-11-24，升级不再写空 fenliu.env 密码）

- 安装器：**升级会把 fenliu.env 里的三个密码写空**（v0.4.3 升级时实测：
  `ADMIN_PASSWORD`/`MIHOMO_SECRET`/`SS_PASSWORD` 全被写成空值；
  管理员密码明文只在 fenliu.env 有，DB 里只有哈希，写空就再也找不回
  来）。现升级时 SS/Mihomo 优先读 DB、DB 没有则继承现有 fenliu.env，
  管理员密码直接继承现有 fenliu.env；三者都不再写空，且能把 v0.4.3
  已写空的机器修回来（SS/Mihomo 从 DB 恢复，管理员密码需 fenliu.env
  仍有值）。运行本身不受影响（服务从 DB 读密钥），但 `verify.sh`
  的配置同步检查依赖 fenliu.env 里的管理员密码，写空后会 SKIP。

## v0.4.3（2026-11-24，面板保存按钮修复）

- 面板：**分流绑定保存按钮一直是禁用的**（Alpine 3.14.8 的坑：
  `x-for` 内 `:disabled="bindingBusy[g.key]"` 在键缺失时（值为
  `undefined`）会把按钮锁死；改用 `!!` 转布尔后恢复正常，测速按钮
  原先已用 `!!` 故不受影响）。此前面板上从未成功保存过一次绑定，
  均由此导致（与 v0.4.1 修的 `groupDrafts` 问题同时存在）。
- 面板：`status`/`batchResult` 改为预填默认结构（原先为 `null`，
  首屏渲染时模板表达式抛错，控制台刷 20 多条 Alpine Expression
  Error；现首屏零报错）。
- 面板：切主节点时自动把该节点从备用里踢掉（后端拒绝主备重叠，
  返回 400；且切主后该节点的备用复选框会被隐藏，用户无法手动取消
  勾选，不处理就是死路）。保存时再滤一次，双保险。

## v0.4.2（2026-11-23，Ubuntu 22.04 兼容修复）

- 安装器：新增 `select_python`——优先系统 `python3`，不够新时找
  `python3.12`/`python3.11`/`python3.13`（Ubuntu 22.04 自带 3.10，
  原先直接报错退出；现用 deadsnakes 的 `python3.11` 即可安装）。
  venv 与 pip 检查、venv 创建均改用选中的解释器；不再建议改系统
  默认 `python3`（会破坏 apt 等工具）。
- 安装器：头部示例克隆地址改为 Gitea（GitHub 仓库尚未发布）。

## v0.4.1（2026-11-23，N1 真机联调修复）
- 安装器：Armbian 的 `venv` 能 import 但缺 `ensurepip`，检测改为
  `import venv, ensurepip`（缺失时自动装 `python3-venv`）。
- 安装器：首跑残留的半残 venv（有 python 无 pip）会被误判为可用，
  现 pip 缺失时清掉重建。
- 面板：分流组绑定下拉框首次加载时因 `groupDrafts` 为空对象导致
  `x-model` 抛错、选择从未生效，现预填 5 个组的草稿。
- 解析器：VLESS 的 `fingerprint` 键改为 mihomo 正确的
  `client-fingerprint`（mihomo 把 `fingerprint` 当 TLS 证书钉扎，
  值 `chrome` 非法致握手直接失败，节点显示离线）。
- README：修正非交互安装调用方式（环境变量 + `--non-interactive`，
  不接受 `VAR=val` 位置参数）。

## v0.4.0（2026-11-23）
- 初始发布：阶段一至四全部完成（后端 + 面板 + 安装器 + Docker 备选）。
