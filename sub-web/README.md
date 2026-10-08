# sub-web

参考 [CareyWang/sub-web](https://github.com/CareyWang/sub-web) 的订阅转换服务，部署在 Cloudflare Pages 上：
同一个站点同时提供网页和转换接口，订阅解析、规则处理和配置生成都在 Pages Functions 里完成，
**不依赖 api.wcc.best 或任何外部 subconverter 后端**。

## 功能

- 网页：填写订阅、选择客户端、手动填写远程配置地址、筛选与重命名节点，生成订阅链接；支持复制、一键导入 Clash、预览转换结果、从已有链接还原表单。
- 远程配置地址默认留空，输入框中的仓库地址仅为示例提示；留空时生成基础策略组。该地址不自动保存或恢复，也可通过解析已有订阅链接回填。
- 接口：`/sub` 的参数与 subconverter 兼容，已有订阅链接换个域名即可使用。
- 输入：Clash / mihomo YAML 订阅、Base64 链接列表、明文链接列表、SIP008 JSON，也可以直接粘贴节点链接；多个来源用换行或 `|` 分隔。
- 协议：ss（含 obfs / v2ray-plugin / shadow-tls）、ssr、vmess、vless（含 Reality / XHTTP）、trojan、hysteria、hysteria2、tuic、anytls、socks5、wireguard。
- 输出：
  - `clash`：mihomo（Clash Meta）完整配置，或配合 `list=true` 只输出节点（proxy-provider）。
  - `mixed`：Base64 分享链接列表，适用于 v2rayN、Shadowrocket 等。
- 外部配置：兼容 subconverter 的 ini 格式（如仓库里的 `clash.ini`、ACL4SSR 在线配置）。
- 自动修正会让 Clash 报错的配置：策略组自引用和循环引用（mihomo 报 `loop is detected in ProxyGroup`）、空策略组、重名节点，以及 Clash 不支持的规则类型（如 `URL-REGEX`、`USER-AGENT`）。修正内容以警告形式写在配置文件开头。

## 目录结构

```
public/            静态网页（无需构建）
functions/         Pages Functions 路由：/sub、/ruleset、/version
src/               转换逻辑
  parsers/         订阅内容与节点链接解析
  generators/      Clash YAML 与分享链接输出
  config.js        外部 ini 配置解析
  rules.js         规则集解析、规范化与 rule-providers
  groups.js        策略组生成（含循环引用处理）
  nodes.js         节点筛选、重命名、Emoji、去重
test/              node:test 测试
```

## 部署到 Cloudflare Pages

### 方式一：连接 Git 仓库

1. Cloudflare 控制台 → Workers & Pages → 创建 → Pages → 连接到 Git，选择本仓库。
2. 构建设置：
   - 框架预设：无
   - 根目录：`sub-web`
   - 构建命令：`npm ci`
   - 构建输出目录：`public`
3. 部署完成后访问 `https://<项目名>.pages.dev`。建议绑定自定义域名，`pages.dev` 在部分网络下访问不稳定。

### 方式二：命令行直接上传

```bash
cd sub-web
npm ci
npx wrangler login
npm run deploy        # 即 wrangler pages deploy，首次会提示创建项目
```

### 访问令牌（可选）

公开部署时，建议在 Pages 项目的「设置 → 变量和机密」里添加加密变量 `ACCESS_TOKEN`。
设置后 `/sub` 与 `/ruleset` 都要求携带 `token=<ACCESS_TOKEN>` 参数；网页会自动显示令牌输入框，
生成的订阅链接和 rule-providers 地址会自动带上令牌。

## 本地开发

```bash
cd sub-web
npm ci
npm run dev    # wrangler pages dev，默认 http://localhost:8788
npm test       # 运行测试
```

## 接口

### `GET /sub`

| 参数 | 说明 |
| --- | --- |
| `target` | `clash`（默认，也接受 `clashmeta`、`mihomo`）或 `mixed`（也接受 `v2ray`、`base64`、`shadowrocket`） |
| `url` | 订阅链接或节点链接，多个用 `\|` 分隔，需 URL 编码 |
| `config` | 外部 ini 配置地址；不填时只生成「节点选择」和「自动选择」两个策略组 |
| `include` / `exclude` | 保留 / 排除节点的正则（匹配原始节点名） |
| `rename` | 重命名规则 `正则@替换`，多条用 `` ` `` 分隔 |
| `emoji` | 是否按地区添加国旗，默认 `true`；`false` 时保留原名称 |
| `udp` / `tfo` / `scv` | 统一设置 UDP、TCP Fast Open、跳过证书验证；不传则保留订阅原设置 |
| `sort` | 按名称排序节点 |
| `append_type` | 节点名前加 `[VMess]` 等类型 |
| `list` | `true` 时只输出 `proxies`，用作 proxy-provider |
| `expand` | `true`（默认，与 subconverter 一致）把规则写入配置；`false` 生成 rule-providers，见下文 |
| `filename` | 通过 `Content-Disposition` 告诉客户端配置名 |
| `ua` | 拉取订阅时使用的 User-Agent，默认 `clash.meta`（多数机场据此返回完整的 mihomo 节点） |
| `token` | 设置了 `ACCESS_TOKEN` 时必填 |

响应头：
- `subscription-userinfo`：透传第一个订阅返回的流量信息，客户端可显示用量与到期时间。
- `X-Node-Count`：节点数量。
- `X-Convert-Warnings`：URL 编码的 JSON 警告列表，网页预览时展示。

### `GET /ruleset?url=<规则集地址>[&type=clash-domain|clash-ipcidr|clash-classic][&token=]`

下载规则集并转换为 mihomo classical 文本，只输出规则行。`expand=false` 生成的 rule-providers 都指向这里，
客户端只要能访问本站就能更新规则，不需要直连 GitHub。

### `GET /version`

返回后端版本，网页用它检测后端状态。

## 外部配置支持的键

| 键 | 说明 |
| --- | --- |
| `ruleset=策略组,地址[,间隔]` | 远程规则集，支持 `clash-domain:` / `clash-ipcidr:` / `clash-classic:` 前缀和 Clash payload YAML |
| `ruleset=策略组,[]GEOIP,CN` | 内联规则，`[]FINAL` 等同 `MATCH` |
| ``custom_proxy_group=名称`类型`成员...`` | `[]名称` 引用策略组或 `DIRECT` 等内置策略，其他成员作为正则匹配节点名；测速类分组末尾为 `` `测速地址`间隔[,超时][,容差] `` |
| `enable_rule_generator` / `overwrite_original_rules` | 是否生成规则 / 是否覆盖 `clash_rule_base` 中的原有规则 |
| `clash_rule_base` | 基础 Clash 配置（端口、DNS 等），不填时使用内置的精简配置 |
| `exclude_remarks` / `include_remarks` | 排除 / 保留节点 |
| `rename` / `emoji` / `add_emoji` / `remove_old_emoji` | 重命名与 Emoji 规则 |

不支持：YAML / TOML 格式的外部配置、本地路径规则集、`!!GROUP=` 等 subconverter 专有写法（会给出警告并忽略）。

## Cloudflare 免费版的限制

| 限制 | 影响 |
| --- | --- |
| 每次请求 CPU 时间 10 ms（偶尔超出可容忍，持续超出返回 1102 错误） | `expand=true` 时要解析并输出全部规则。本仓库 `clash.ini` 约 1.5 万条规则，单次转换 CPU 约 20–50 ms，**免费版请使用 `expand=false`**（网页默认不展开），此时约 6–12 ms。付费版（Workers Paid）没有这个问题。 |
| 每次请求最多 50 个子请求 | `expand=true` 时订阅、外部配置和每个规则集各算一个。本仓库 `clash.ini` 为 34 个（订阅 1 + 配置 1 + 规则集 32），未超限；规则集更多时请用 `expand=false`。 |

`expand=false` 时，每个规则集由客户端单独请求 `/ruleset`，每次只处理一个规则集，不受上述限制。
规则集和外部配置经 Cloudflare 边缘缓存（规则集 1 小时、外部配置 5 分钟），订阅内容不缓存。

## 与 subconverter 的差异

- `target=clash` 输出 mihomo 配置（vless、hysteria2、tuic、anytls 等仅 mihomo 支持），不再兼容已停止维护的 Clash Premium。
- 暂不支持 Surge、Quantumult X、Loon、sing-box 等目标格式。
- 不提供短链接和配置上传服务（这两项在 sub-web 中依赖外部服务）。
