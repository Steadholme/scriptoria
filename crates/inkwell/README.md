# Inkwell — 个人博客 / CMS（SSO 写作）

Inkwell 是 Steadholme 主权基础设施栈中的 **个人博客 / CMS** 服务：一个干净的阅读视图 + 一个 Markdown 写作表单。访客通过 **Sluice 网关** 的 SSO 登录后即可撰写、编辑、删除 **自己的** 文章；文章正文以 Markdown 撰写，渲染为 **经过净化的 HTML**。

技术栈与 keystone/keyward/beacon 一致：**Rust + axum**，sqlx 运行期查询（无编译期宏、无数据库即可构建），rustls（无 OpenSSL）。数据层只用 **可移植标准 SQL**（`TEXT/BIGINT/BOOLEAN` + `PK/UNIQUE/NOT NULL/DEFAULT`），日后可在 FusionDB 上经 pgwire 原样运行。

## 角色与定位

- **仅内网服务**：Inkwell 不直接对公网暴露，统一经 **Sluice 网关** 反代，落在子域 `blog.w33d.xyz` 根路径（网关 **不剥前缀**，原样转发路径）。
- **不做自有登录**：整站坐落在 Sluice `auth=sso` 路由后。网关完成 OIDC 浏览器登录、**剥离**任何入站 `X-Auth-*` 后注入可信身份头（`X-Auth-Subject` / `X-Auth-Email`）。Inkwell 直接 **信任** 这些头作为文章作者与 app-bar 的「已登录为」。**作者身份永远取自网关头，绝不信任客户端提交的字段**。登出走 `https://id.w33d.xyz/_gw/auth/logout`。

## 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/healthz` | GET | 200 `ok`，容器 HEALTHCHECK 使用 |
| `/` | GET | 首页：文章列表（最新在前，标题 + 摘要 + 日期 + 作者） |
| `/p/{slug}` | GET | 单篇文章，正文 Markdown 渲染为净化 HTML |
| `/new` | GET / POST | 撰写表单 / 创建（slug 由标题生成，作者取自 `X-Auth-*`） |
| `/edit/{slug}` | GET / POST | 编辑 **自己的** 文章（slug 保持稳定，不破坏外链） |
| `/delete/{slug}` | POST | 删除 **自己的** 文章 |

- **草稿可见性**：`published=false` 的文章只有作者本人能在首页看到（带 `Draft` 徽章）并访问 `/p/{slug}`；其他访客返回 404。
- **所有权**：编辑 / 删除仅限文章作者（`author_sub == X-Auth-Subject`），否则 403。

## 安全

- **CSRF（double-submit）**：所有状态变更 POST（新建 / 编辑 / 删除）都要求隐藏字段 `csrf_token` 与 `__Host-csrf` cookie 常量时间相等。token 一次铸造、跨页复用（cookie 生命周期内多标签页稳定）。
- **Markdown 净化**：渲染在 **事件层** 净化——原始块级 / 内联 HTML 事件转义为文本（`<script>` 只会作为字面字符出现），链接 / 图片 URL 仅白名单 `http/https/mailto/tel` 与相对路径，其余（如 `javascript:`）改写为 `#`。所有插值字段额外 HTML 转义（纵深防御）。

## 数据模型（可移植标准 SQL）

```sql
posts(
  id TEXT PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  body_md TEXT NOT NULL,
  author_sub TEXT NOT NULL,
  author_email TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  published BOOLEAN NOT NULL DEFAULT TRUE
)
```

启动时幂等执行 `CREATE TABLE IF NOT EXISTS` + 一个 `created_at` 索引（支撑最新在前的列表扫描）。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `BIND_ADDR` | `0.0.0.0:8700` | 监听地址 |
| `INKWELL_STORE` | `memory` | `memory`（无数据库）或 `postgres` |
| `DATABASE_URL` | — | `INKWELL_STORE=postgres` 时必填，指向 `postgres:5432/inkwell` |

## 构建与测试

```bash
cd /root/w33d_infra/inkwell

cargo build                                   # 无需数据库
cargo clippy --all-targets -- -D warnings     # 零告警
cargo test                                    # 默认全内存存储，无需数据库

# Postgres 集成测试（需外部 Postgres；未设置 TEST_DATABASE_URL 时自动跳过）
docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=inkwell \
  -p 127.0.0.1:55460:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55460/inkwell \
  cargo test --test pg_store -- --nocapture
```

测试覆盖：健康检查；空首页占位；无身份 / CSRF 不匹配的 POST → 401；创建（标题生成 slug）；首页与阅读视图渲染；Markdown XSS 净化；非作者编辑 / 删除 → 403；作者编辑（slug 稳定）/ 删除；草稿仅作者可见。

## Docker

多阶段、非 root（uid 10001）、纯 Rust + rustls（无 OpenSSL）、内置 `inkwell healthcheck` 子命令、`EXPOSE 8700`。

```bash
docker build -t holdfast/inkwell:dev .
docker run -d --name inkwell -p 127.0.0.1:8700:8700 \
  -e INKWELL_STORE=postgres -e DATABASE_URL=$DATABASE_URL \
  holdfast/inkwell:dev
curl -fsS http://127.0.0.1:8700/healthz       # ok
```

## 部署接线（交给 deploy）

- 在 `holdfast` 网络内新增 `inkwell` 服务，`INKWELL_STORE=postgres` + 指向新建数据库 `inkwell` 的 `DATABASE_URL`，**仅内网**（不发布公网端口）。
- 部署期创建数据库 `inkwell`。
- Sluice 路由表新增：`blog.w33d.xyz`（path_prefix `/`）→ 上游 `http://inkwell:8700`、`auth=sso`。通配 `*.w33d.xyz` DNS 已解析到本机，autocert 首次握手即签发 LE 证书，无需 DNS 动作。
- Portal 磁贴：名称 `Blog`，描述「个人博客与札记」，icon 提示 `mail`/文档类；Beacon 组件名 `Blog`。
