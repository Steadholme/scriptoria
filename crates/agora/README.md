# Agora

Steadholme 的讨论论坛（discussion forum）。服务端渲染（server-rendered）的企业级 UI，身份认证完全交给
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

Agora 的产品入口位于公网域名，但应用端口只在服务网络中可达；所有浏览器请求必须先经过 Sluice 的
`auth=sso` 路由。Agora 仅信任网关剥离并重新注入、且在生产中由 HMAC 签名的身份头。退出登录链接指向网关：
`https://id.w33d.xyz/_gw/auth/logout`。

状态变更类的 POST（发主题、回帖）额外加了 **CSRF 双提交（double-submit）** 防护：一个可被 JS 读取的
`__Host-csrf` Cookie，其值必须与表单提交的 token 一致。

## 端点（endpoints）

| 方法 + 路径            | 说明                                                      |
|------------------------|-----------------------------------------------------------|
| `GET  /healthz`        | 存活探针（容器 HEALTHCHECK 使用），返回 `200 ok`          |
| `GET  /`               | 分类列表（含主题数）+ 最近活跃主题                        |
| `GET  /questions`      | 跨 Question 分类的 Answer Desk，可筛 Answered/Unanswered |
| `GET  /c/{id}`         | 某分类下的主题列表                                        |
| `GET  /t/{id}`         | 某主题：原帖 + 回复（Markdown 渲染）+ 回复表单            |
| `GET  /new?cat=`       | 发新主题的表单（可用 `cat` 预选分类，含「相似主题」实时提示） |
| `POST /new`            | 创建主题（CSRF + 身份校验）                               |
| `POST /t/{id}/reply`   | 发表回复（CSRF + 身份校验）                               |
| `POST /t/{id}/accept`  | Question 分类中由主题作者或管理员采纳/取消采纳回答        |
| `POST /t/{id}/subscribe` | 明确关注或取消关注主题（CSRF + 身份校验）               |
| `GET  /activity`       | 个人 Activity Inbox；支持未读与原因筛选、稳定游标分页     |
| `POST /activity/{id}/open` | 将一条 Activity 标为已读，再 `303` 跳转到权威主题位置 |
| `POST /activity/{id}/state` | 将一条 Activity 标为已读或未读（CSRF + 重新授权）     |
| `POST /activity/read-page` | 将当前页最多 30 条 Activity 原子标为已读（CSRF + 逐条重新授权） |
| `GET  /search`         | 搜索标题、原帖及 accepted solution，可筛分类与回答状态    |
| `GET  /api/search/suggest` | 同源快捷搜索建议（含 solution 命中来源）              |
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
    sort_order BIGINT NOT NULL DEFAULT 0,
    format TEXT NOT NULL DEFAULT 'discussion'
);
CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    category_id TEXT NOT NULL,
    title TEXT NOT NULL,
    author_sub TEXT NOT NULL,
    author_email TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_at BIGINT NOT NULL,
    first_body_md TEXT NOT NULL DEFAULT '',
    first_post_id TEXT NOT NULL DEFAULT '',
    locked BOOLEAN NOT NULL DEFAULT FALSE,
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    accepted_post_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE posts (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    body_md TEXT NOT NULL,
    quoted_post_id TEXT NOT NULL DEFAULT '',
    author_sub TEXT NOT NULL,
    author_email TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
```

个人 Activity 由以下可移植表承载：`forum_activity_events` 只保存事件类型、主题/帖子与行为者等
权威指针；`forum_activity_deliveries` 保存收件人与触发原因；`forum_activity_receipts` 保存每位用户的
已读状态。主题标题与帖子正文不复制进事件表，读取时始终 JOIN 当前的 `threads` / `posts` 数据。显式关注关系
保存在 `thread_subscriptions`，以上表与索引都通过幂等迁移创建。

启动时执行幂等迁移；旧分类仅在 `format IS NULL` 时一次性回填，之后重启不会覆盖管理员选择。若分类表为空，
则种入默认分类：Announcements / General Discussion 为 `discussion`，Support 为 `question`。

## Q&A Answer Desk

- Category format 是持久化产品语义，不是 CSS 标签：`discussion` 保持开放讨论；`question` 才能采纳回答。
- `status=answered|unanswered` 在全局列表和搜索中都隐式限定为 Question 分类，避免把普通讨论误判为待回答。
- Accepted solution 固定展示在原帖下方，并在分页查询执行 `LIMIT` 前排除，因此不会因为自然位置落在第 2 页而消失或重复。
- 搜索同时覆盖标题、原帖与 accepted solution；solution 命中会返回对应 excerpt，而不是误展示原帖摘要。
- 将含 accepted solution 的 Question 分类改为 Discussion，或把 answered thread 移入 Discussion，都会被后端拒绝；必须先取消采纳。

## Durable Activity Inbox

- 发回复与生成 reply、mention、主题作者、引用作者和关注者的 Activity 在同一个 Store 命令中原子提交；
  accepted answer 的变更与对应 Activity 同样原子提交。
- 同一事件对同一收件人去重并抑制行为者本人；多个原因命中时使用稳定优先级，mention 优先于 reply / following。
- Activity 支持 All / Unread 和 Mentions / Replies / Following / Answers 筛选，以及稳定 keyset 分页。
- 单条操作和批量操作都会重新检查当前用户与权威主题/帖子；“Mark this page read”最多接受 30 个 ID，
  任一 ID 不可访问时整批回滚。页面渲染后产生的新事件不会被误标为已读。
- 打开一条 Activity 会先持久化已读状态，再跳转到包含目标回复的正确分页位置。Activity 的已读状态是个人
  分诊状态，不等同于主题阅读进度。
- 新建 Activity 表不会回填历史事件，避免部署后把全部历史回复变成未读；删除主题或帖子时会同步清理对应事件。

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
  cargo test --test pg_store --test pg_search --test pg_activity -- --nocapture --test-threads=1
docker rm -f agora-testpg

# 容器镜像
docker build -t steadholme/agora:dev .
```

## 安全要点

- **身份**：作者只来自 `X-Auth-Subject`/`X-Auth-Email`，从不信任客户端字段。
- **CSRF**：状态变更 POST 走 `__Host-csrf` 双提交校验（常量时间比较）。
- **XSS**：Markdown 渲染时把原始 HTML 降级为纯文本、把 `javascript:`/`data:` 等危险 scheme 的
  链接/图片地址改写为 `#`；其余插值文本一律 HTML 转义。

## 设计

Rust + axum，沿用 Steadholme 共享品牌令牌（brand tokens）：深蓝渐变品牌、靛蓝强调色、柔和卡片与阴影，
顶栏含 Steadholme 盾徽 + 服务名 + 当前登录邮箱 + 退出链接。CSS 通过 `include_str!` 内联，无静态资源往返。
