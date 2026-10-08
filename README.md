# rules

个人使用的 Clash 分流规则，以及一个部署在 Cloudflare Pages 上的订阅转换服务。

- `clash.ini` 是 subconverter 格式的远程配置，定义规则集引用和策略组，用来把机场订阅转换成带分流规则的 Clash 配置。
- `*.list`、`anthropic.ini` 是自己维护的规则集，由 `clash.ini` 引用。
- `sub-web/` 是订阅转换服务，网页和转换接口都在自己的 Cloudflare Pages 上运行，不依赖第三方 subconverter 后端。

## 目录

| 路径 | 内容 |
| --- | --- |
| `clash.ini` | 远程配置：规则集引用（`ruleset`）和策略组（`custom_proxy_group`） |
| `anthropic.ini` | Anthropic / Claude 分流规则，交给「💬 Anthropic」策略组 |
| `cursor.list` | Cursor 分流规则，交给「🐙 Cursor」策略组 |
| `ruleset-my.list` | 自己的域名，直连 |
| `sub-web/` | 订阅转换服务，见 [sub-web/README.md](sub-web/README.md) 和 [sub-web/实现说明.md](sub-web/实现说明.md) |
| `.agents.md` | AI 编程助手在本仓库的工作约定 |

`docs/` 目录只保存在本地，已被 `.gitignore` 忽略，不会提交。

## 使用方法

转换订阅时，把下面的地址填到「远程配置」里：

```
https://raw.githubusercontent.com/scoke/rules/refs/heads/main/clash.ini
```

可以用本仓库的 `sub-web`，也可以用其他兼容 subconverter 的转换服务。

本仓库规则文件的地址格式相同，例如：

```
https://raw.githubusercontent.com/scoke/rules/refs/heads/main/anthropic.ini
https://raw.githubusercontent.com/scoke/rules/refs/heads/main/cursor.list
https://raw.githubusercontent.com/scoke/rules/refs/heads/main/ruleset-my.list
```

## clash.ini 的分流逻辑

### 规则顺序

Clash 从上到下匹配规则，命中第一条后不再继续。`clash.ini` 里 `ruleset` 的顺序就是匹配顺序：

1. 局域网地址、`UnBan` 列表 → 「🎯 全球直连」
2. 具体服务：Adobe、微软、苹果、Telegram、OpenAI、Gemini、Google AI、Anthropic、Docker、开发工具、Cursor、GitHub、游戏平台 → 各自的策略组
3. 国内媒体 → 「🌏 国内媒体」（直连）
4. GFW 列表及补充列表 → 「🚀 节点选择」
5. 国内 IP、国内域名、国内公司 IP、下载服务、Google 中国、`ruleset-my.list` 等 → 「🎯 全球直连」
6. `GEOIP,LAN`、`GEOIP,CN` → 「🎯 全球直连」
7. 其余流量 → 「🐟 漏网之鱼」

服务规则要放在 GFW 列表和国内列表前面，否则会先被这些大范围列表命中。

### 策略组

| 策略组 | 默认选项 | 说明 |
| --- | --- | --- |
| 🚀 节点选择 | 🚀 手动切换 | 通用代理入口，可切到各地区分组或直连 |
| 🚀 手动切换 | 🇺🇲 美国节点 | 在各地区分组之间手动选择 |
| 💬 OpenAi、💬 Gemini、💬 GoogleAI | 🇺🇲 美国节点 | AI 服务默认走美国 |
| 💬 Anthropic | 🇺🇲 美国节点 | 只有美国节点一个选项 |
| Ⓜ️ 微软Bing、Ⓜ️ 微软云盘、Ⓜ️ 微软服务、🍎 苹果服务、🎮 游戏平台 | DIRECT | 默认直连，需要时切到代理 |
| 📲 电报消息、🍃 Adobe | 🚀 节点选择 | Adobe 还可以选 REJECT 拦截 |
| 🐳 dockerHub、🐳 开发、🐙 Github、🐙 Cursor | 🚀 节点选择 | 开发相关 |
| 🎯 全球直连 | DIRECT | 直连，需要时可切到代理 |
| 🌏 国内媒体、🎮 游戏平台(steamCN) | DIRECT | 只有直连一个选项 |
| 🐟 漏网之鱼 | 🇺🇲 美国节点 | 未命中任何规则的流量 |
| 🇭🇰 🇯🇵 🇺🇲 🇨🇳 🇸🇬 🇰🇷 地区分组 | — | 按节点名称中的地区关键字自动归类；美国分组还包含自建节点 `scoke` |

完整定义以 `clash.ini` 为准。

## 修改规则

- **给已有服务加域名**：编辑对应的规则文件，例如在 `anthropic.ini` 里加一行 `DOMAIN-SUFFIX,example.com`。
- **新增一个服务**：
  1. 新建规则文件（如 `xxx.list`）。
  2. 在 `clash.ini` 中加 `ruleset=策略组名,规则文件地址`。注意按上面的顺序放在合适位置。
  3. 加对应的 `custom_proxy_group=策略组名` 一行。
- **策略组之间不要互相引用**，例如 A 包含 B、B 又包含 A，也不要引用自己。mihomo 加载时会报 `loop is detected in ProxyGroup` 并拒绝整个配置。`sub-web` 会自动删掉形成循环的引用并给出警告，其他转换服务不一定会这样处理。
- 规则文件每行一条，格式为 `类型,值`，不写策略组名（策略组由 `clash.ini` 指定）。`#` 开头的行是注释。

修改推送后不会立即生效：

- GitHub raw 地址有几分钟的缓存。
- `sub-web` 会在 Cloudflare 上缓存远程配置 5 分钟、规则集 1 小时。
- 客户端需要重新更新订阅；使用 rule-providers 时，规则集按各自的更新间隔刷新。

## sub-web

订阅转换服务。在 Cloudflare Pages 上运行，提供网页和兼容 subconverter 参数的 `/sub` 接口，直接解析订阅并生成 Clash（mihomo）配置。

```bash
cd sub-web
npm ci
npm run dev    # 本地运行，默认 http://localhost:8788
npm test
```

部署方法、接口参数和 Cloudflare 免费版的限制见 [sub-web/README.md](sub-web/README.md)；处理流程和代码结构见 [sub-web/实现说明.md](sub-web/实现说明.md)。

## 注意

本仓库是公开的，不要提交订阅地址、节点密码、服务器管理信息或访问令牌。这类内容放在 `docs/` 等已忽略的目录，或只保存在本地。
