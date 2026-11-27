# LanMux 锁定的决策

开发过程中锁定的设计决策记录。原载于 README.md，v1.0.0 文档重写时移至此处，内容按原样保留（个别章节引用已改为指向 README.md 的现行章节）。

- **核心**：metacubex/mihomo（fallback 策略组 + 成熟的 Clash REST API
  是这个项目控制面的基础；sing-box 适合做 VPS 出站客户端，不适合做
  中央分流器）。
- **部署方式**：两种，同仓。① 原生二进制 + systemd（主推），部署在
  局域网常驻设备（小主机 / NAS / Linux 服务器），见 `install.sh`；
  ② Docker 单镜像 All-in-One（mihomo + 面板同容器，见 README.md 的
  Docker 部署一节）。路径与 URL 全部可配置：Mihomo API 默认
  `http://127.0.0.1:9090`，配置输出路径可配置，开发默认
  `./data/mihomo/config.yaml`。
- **Web UI**（阶段三）必须是全功能自有面板（节点管理、规则绑定、
  诊断），metacubexd 只作为查看连接日志的补充入口。
- **红线**：不做透明网关/旁路由（无 iptables/nftables/TProxy/TUN）；
  不引 Redis/MySQL/Nginx；局域网总入口不套 TLS/WS/Reality。
- **管理员密码**：首次启动时由 `ADMIN_PASSWORD` 环境变量预置并以
  PBKDF2 哈希存入 settings（默认密码写进安装命令）；登录后在网页设置
  里改密码，不走手动改密码流程。改密码后所有登录 Token 失效。
- **Mihomo 二进制**（阶段四安装器）：从 GitHub release 下载，镜像兜底；
  版本钉选 **v1.19.34**（`install.sh` 的 `MIHOMO_VERSION`，有新版时改
  这里重跑即升级）。校验：有 `checksums.txt` 时验 sha256，否则验体积
  + `--version` 烟囱测试（v1.19.34 不发布 checksums.txt，实测确认）。
- **Geodata**（GeoSite/GeoIP）：默认 metacubex GitHub releases，环境变量
  可覆盖镜像源。安装阶段预置到数据目录，按 mihomo 约定命名为
  `GeoIP.dat` / `GeoSite.dat` / `Country.mmdb`，启动时不再联网拉取。
- **metacubexd**（阶段四）：安装器下载 v1.276.0 `compressed-dist.tgz`
  并解压到数据目录下的 `ui/`，生成配置时写 `external-ui`。**注意：
  external-ui 必须是 mihomo 家目录（`-d`，即 `/etc/lanmux`）
  的子路径**，否则 `mihomo -t` 直接报 `not subpath of home directory`
  拒绝启动（真实 mihomo v1.19.34 实测；与 mihomo-gateway 的
  `/etc/mihomo/ui` 约定一致）。
- **N1 共存**（阶段四）：N1 上已有旧 mihomo-gateway 的 `mihomo` 单元
  + `/etc/mihomo`，安装器**绝不碰**它们。LanMux 用独立的单元名
  （`lanmux-mihomo` / `lanmux-web`）与独立路径（代码 `/opt/lanmux`、
  数据 `/etc/lanmux`）；预检检查全部四个端口，冲突时报错并
  给出换端口的环境变量（见 README.md 的配置与端口一节）。
- **测速**：最多 5 并发，每节点 5 秒超时；结果存回节点行。
- **`url-test` 组不写 `tolerance`**，用 Mihomo 默认 50。
- **前端登录态**：Token 放 `localStorage`（局域网面板，手机 + 电脑
  共用，每次刷新重登录太烦；服务端 24 小时过期不变）。
- **SS 二维码**：后端给现成链接（`GET /api/settings/ss-link`），
  前端只负责渲染；二维码库 vendored 进页面（qrcode-generator，MIT），
  无外网也能生成。
- **`speedtest-all` 是同步接口**（最多约 5 秒）：前端用加载态等，
  不另加异步任务接口。
- **metacubexd 入口**：纯外链，新标签页打开，不嵌 iframe。
- **首次启动无管理员密码**：前端显示设置向导，
  `POST /api/auth/setup` 只在未配置时可设密码并直接登录。
