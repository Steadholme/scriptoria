# Agora

HOLDFAST 的讨论论坛（discussion forum）。服务端渲染（server-rendered）的企业级 UI，身份认证完全交给
网关 SSO，自身不做任何登录。

- **子域名**：`forum.w33d.xyz`（经 Sluice 网关，`auth=sso`）
- **内部端口**：`8710`（仅内网可达，不对外暴露端口）
- **数据库**：`agora`（Postgres，服务独占自己的库）

## 是什么

Agora 是一个分类讨论区：

- **分类（categories）** 下挂 **主题（threads）**，主题里是 **帖子（posts）**。
- 每个主题的第一帖是「原帖」，其余是回复。
- 帖子正文用 CommonMark（Markdown）撰写，渲染时经过净化（sanitised），杜绝脚本注入。

作者身份永远取自网关注入的 `X-Auth-Subject` / `X-Auth-Email`，**绝不**信任客户端传来的作者字段。

## 网关 SSO 模型

Agora 跑在 Sluice 的 `auth=sso` 路由后面：网关负责对接 Keystone 完成 OIDC 浏览器登录，**剥离**所有入站
`X-Auth-*` 头，再注入经过校验的：

- `X-Auth-Subject` — 用户 sub（作者主键）
- `X-Auth-Email` — 用户邮箱（顶栏「signed in as」+ 作者展示）
- `X-Auth-Scope` — 授权范围

因为 Agora 是内网专属（never publicly reachable），所以它**信任**这些头作为已认证用户。退出登录链接指向网关：
`https://id.w33d.xyz/_gw/auth/logout`。

状态变更类的 POST（发主题、回帖）额外加了 **CSRF 双提交（double-submit）** 防护：一个可被 JS 读取的
`__Host-csrf` Cookie，其值必须与表单提交的 token 一致。

## 端点（endpoints）

| 方法 + 路径            | 说明                                                      |
|------------------------|-----------------------------------------------------------|
| `GET  /healthz`        | 存活探针（容器 HEALTHCHECK 使用），返回 `200 ok`          |
| `GET  /`               | 分类列表（含主题数）+ 最近活跃主题                        |
| `GET  /c/{id}`         | 某分类下的主题列表                                        |
| `GET  /t/{id}`         | 某主题：原帖 + 回复（Markdown 渲染）+ 回复表单            |
| `GET  /new?cat=`       | 发新主题的表单（可用 `cat` 预选分类，含「相似主题」实时提示） |
| `POST /new`            | 创建主题（CSRF + 身份校验）                               |
| `POST /t/{id}/reply`   | 发表回复（CSRF + 身份校验）                               |
| `POST /api/similar`    | （CSRF + 身份校验）按草稿 `{title,body}` 返回最相似的 3 个现有主题（JSON），编辑时去重 |
| `GET  /api/thread/{id}/summary` | 某主题的抽取式摘要（top 句子，本地确定性算法，无外部 LLM），JSON |

所有页面都在子域名 **根路径** 提供服务（Sluice 原样转发路径，不做前缀剥离）。

## 数据模型（portable standard SQL）

仅使用可移植的标准 SQL（`TEXT`/`BIGINT`，`PRIMARY KEY`/`NOT NULL`/`DEFAULT`，参数化查询，
`INSERT .. ON CONFLICT`，普通索引），不用 JSONB/数组/SERIAL/扩展，因此日后可原样跑在
FusionDB（over pgwire）上。

```sql
CREATE TABLE categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sort_order BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    category_id TEXT NOT NULL,
    title TEXT NOT NULL,
    author_sub TEXT NOT NULL,
    author_email TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_at BIGINT NOT NULL
);
CREATE TABLE posts (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    body_md TEXT NOT NULL,
    author_sub TEXT NOT NULL,
    author_email TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
```

启动时执行幂等的 `CREATE TABLE IF NOT EXISTS` 迁移；若分类表为空，则种入默认分类
（Announcements / General Discussion / Support）。

## 存储后端（async-trait Store）

`Store` 是一个 `async-trait` 抽象，handler 只依赖该 trait：

- `InMemoryStore` — 内存实现，让默认测试与开发完全无需数据库。
- `PgStore` — 原生 `await` sqlx（运行时查询，**无** `query!`/`query_as!` 宏；**无**
  `block_in_place`、**无** 同步套异步的桥接），所以 DB 往返绝不阻塞 worker 线程。

由 `AGORA_STORE` 选择（`memory` 默认 / `postgres`）。

## 环境变量

| 变量            | 默认值             | 说明                                            |
|-----------------|--------------------|-------------------------------------------------|
| `BIND_ADDR`     | `0.0.0.0:8710`     | 监听地址                                        |
| `AGORA_STORE`   | `memory`           | `memory` 或 `postgres`                          |
| `DATABASE_URL`  | —                  | `AGORA_STORE=postgres` 时必填，指向 `.../agora` |

## 构建与测试

```bash
# 默认测试（无需数据库）
cargo test
cargo clippy --all-targets -- -D warnings

# Postgres 集成测试（一次性丢弃容器）
docker run --rm -d --name agora-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=agora \
  -p 127.0.0.1:55461:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55461/agora \
  cargo test --test pg_store -- --nocapture
docker rm -f agora-testpg

# 容器镜像
docker build -t holdfast/agora:dev .
```

## 安全要点

- **身份**：作者只来自 `X-Auth-Subject`/`X-Auth-Email`，从不信任客户端字段。
- **CSRF**：状态变更 POST 走 `__Host-csrf` 双提交校验（常量时间比较）。
- **XSS**：Markdown 渲染时把原始 HTML 降级为纯文本、把 `javascript:`/`data:` 等危险 scheme 的
  链接/图片地址改写为 `#`；其余插值文本一律 HTML 转义。

## 设计

Rust + axum，沿用 HOLDFAST 共享品牌令牌（brand tokens）：深蓝渐变品牌、靛蓝强调色、柔和卡片与阴影，
顶栏含 HOLDFAST 盾徽 + 服务名 + 当前登录邮箱 + 退出链接。CSS 通过 `include_str!` 内联，无静态资源往返。
