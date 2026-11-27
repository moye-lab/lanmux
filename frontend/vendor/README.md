# frontend/vendor — 本地化的前端依赖（v0.9.5 起）

面板曾从 CDN 在线加载 Alpine.js 与 Tailwind Play CDN；2026-11-24
实测用户电脑宽带到 jsdelivr 被连接重置（`ERR_CONNECTION_RESET`），
Alpine 拿不到、x-cloak 内容永不显示，整页空白。此后两个依赖全部
随面板同源 served（后端 catch-all 直接 serves `frontend/` 下的文件），
内网断外网也能开。**不要改回 CDN 引用。**

Tailwind Play CDN 已于 v1.0.0 供应链加固（审计 L-41）中移除：Play CDN
是开发版形态（浏览器内实时编译全量 CSS、无 tree-shaking），上游文档
明确说明仅供开发使用。面板现在加载编译好的静态 CSS（`tailwind.css`，
20,410 字节，相对 Play CDN 407,279 字节缩小约 20 倍），`index.html`
里只剩一个 `<link rel="stylesheet" href="/vendor/tailwind.css">`。
`tailwind.js`（Play CDN）已删除，不要恢复。

| 文件 | 来源 | 版本 | sha256（完整 64 位） |
|---|---|---|---|
| `alpine.min.js` | https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js | 3.14.8 | `b600e363d99d95444db54acbfb2deffec9ae792aa99a09229bcda078e5b55643` |
| `tailwind.css` | 由 tailwindcss 3.4.17 CLI 从 `frontend/index.html` 编译（见下） | 3.4.17 编译产物 | `99d295c297cb5229fe01d1b43f7b59a470121d52b8c66bdc1fab67ca854060de` |

哈希为完整 sha256（审计 L-42：此前只记前 16 位，碰撞门槛不足）。
`backend/tests/test_repo_layout.py` 内有 vendor 文件哈希断言，文件被
替换/篡改时测试即失败。复核：`sha256sum frontend/vendor/*`。

## 升级方法

- **Alpine**：从上表来源 URL 重新下载覆盖，核对文件内含 `3.14.8`，
  更新本表与 `index.html` 头部的注释。
- **Tailwind**：不要直接下载 Play CDN。改 `frontend/index.html` 的
  class 或根目录 `tailwind.config.js` 后，在仓库根目录重编：

  ```bash
  npx --yes tailwindcss@3.4.17 -c tailwind.config.js \
    -i tailwind.input.css -o frontend/vendor/tailwind.css --minify
  ```

  编译配置（`content: ['./frontend/index.html']`、字体栈）与
  `index.html` 内原先的内联 `tailwind.config` 保持一致。重编后更新
  本表哈希，并跑 `pytest tests/test_spa_fallback.py`（内含“面板无
  CDN 引用、vendor 文件可 served”的回归测试）与
  `tests/test_repo_layout.py`（哈希断言）。
