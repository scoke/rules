// 转换主流程：下载订阅与外部配置 → 解析节点 → 生成策略组与规则 → 输出目标格式。

import YAML from 'yaml';
import { parseExternalConfig } from './config.js';
import { parseSubscription } from './parsers/subscription.js';
import { processNodes } from './nodes.js';
import { buildGroups, BUILTIN_POLICIES, DEFAULT_GROUP_DEFS, DEFAULT_RULES } from './groups.js';
import { buildProvider, normalizeRule, parseRuleList, RuleCollector } from './rules.js';
import { DEFAULT_CLASH_BASE, generateClash } from './generators/clash.js';
import { generateLinks } from './generators/links.js';
import { encodeBase64, parseBool, QueryParams, splitList } from './utils.js';

export const DEFAULT_UA = 'clash.meta';
const MAX_BODY_BYTES = 20 * 1024 * 1024;

// 参数或输入内容有误，返回 400
export class UserError extends Error {}

const TARGETS = {
  clash: 'clash',
  clashmeta: 'clash',
  'clash.meta': 'clash',
  meta: 'clash',
  mihomo: 'clash',
  mixed: 'mixed',
  v2ray: 'mixed',
  v2rayn: 'mixed',
  base64: 'mixed',
  shadowrocket: 'mixed',
};

// 用 QueryParams 而不是 URLSearchParams：订阅地址、正则里的 "+" 都是字面量，不能变成空格。
export function parseOptions(requestUrl) {
  const q = new QueryParams(new URL(requestUrl).search.slice(1));
  const rawTarget = (q.get('target') || 'clash').toLowerCase();
  const target = TARGETS[rawTarget];
  if (!target) throw new UserError(`不支持的 target：${rawTarget}（可选 clash、mixed）`);
  const url = q.get('url');
  if (!url) throw new UserError('缺少 url 参数');
  const optBool = (k) => parseBool(q.get(k), undefined);
  return {
    target,
    sources: url.split(/[|\r\n]+/).map((s) => s.trim()).filter(Boolean),
    config: (q.get('config') || '').trim(),
    include: q.get('include') || '',
    exclude: q.get('exclude') || '',
    renames: splitList(q.get('rename'), '`')
      .map((r) => {
        const at = r.indexOf('@');
        return at > 0 ? { pattern: r.slice(0, at), replacement: r.slice(at + 1) } : null;
      })
      .filter(Boolean),
    emoji: optBool('emoji'),
    udp: optBool('udp'),
    tfo: optBool('tfo'),
    scv: optBool('scv'),
    sort: parseBool(q.get('sort'), false),
    appendType: parseBool(q.get('append_type'), false),
    list: parseBool(q.get('list'), false),
    expand: parseBool(q.get('expand'), true),
    filename: q.get('filename') || '',
    ua: q.get('ua') || DEFAULT_UA,
    // rule-providers 的下载地址：本站 /ruleset，并带上访问令牌
    relay: { origin: new URL(requestUrl).origin, token: q.get('token') || '' },
  };
}

export function createFetcher(fetchImpl = fetch) {
  return async function fetchText(url, { ua = DEFAULT_UA, cacheTtl, timeoutMs = 15000 } = {}) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error('链接格式无效');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('只支持 http / https 链接');
    const init = {
      headers: { 'User-Agent': ua, Accept: '*/*' },
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
    };
    // Cloudflare 边缘缓存，减少对 GitHub 等规则源的重复请求
    if (cacheTtl) init.cf = { cacheTtl, cacheEverything: true };
    let res;
    try {
      res = await fetchImpl(parsed.toString(), init);
    } catch (e) {
      if (/too many subrequests/i.test(e.message)) {
        throw new Error('超出 Cloudflare 单次请求的子请求上限，可改用 expand=false（规则集由客户端下载）');
      }
      throw new Error(e.name === 'TimeoutError' ? '请求超时' : e.message);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length') || 0);
    if (len > MAX_BODY_BYTES) throw new Error('内容过大');
    const text = await res.text();
    if (text.length > MAX_BODY_BYTES) throw new Error('内容过大');
    return { text, headers: res.headers };
  };
}

export async function convert(opts, fetchText) {
  const warnings = [];

  let cfg = parseExternalConfig('', warnings);
  if (opts.config) {
    let text;
    try {
      ({ text } = await fetchText(opts.config, { cacheTtl: 300 }));
    } catch (e) {
      throw new UserError(`外部配置下载失败：${e.message}`);
    }
    try {
      cfg = parseExternalConfig(text, warnings);
    } catch (e) {
      throw new UserError(e.message);
    }
  }
  const groupDefs = cfg.groups.length ? cfg.groups : DEFAULT_GROUP_DEFS;
  const fullClash = opts.target === 'clash' && !opts.list;
  const generateRules = fullClash && cfg.enableRuleGenerator && cfg.rulesets.length > 0;

  const [sources, base, ruleLists] = await Promise.all([
    loadSources(opts, fetchText, warnings),
    fullClash && cfg.clashRuleBase ? loadBase(cfg.clashRuleBase, fetchText, warnings) : null,
    generateRules && opts.expand ? loadRuleLists(cfg.rulesets, fetchText) : new Map(),
  ]);

  const parsed = sources.flatMap((s) => s.proxies);
  if (!parsed.length) {
    throw new UserError(['没有解析到任何节点', ...warnings].join('\n'));
  }
  const reserved = new Set([...groupDefs.map((g) => g.name), ...BUILTIN_POLICIES]);
  const proxies = processNodes(parsed, opts, cfg, reserved, warnings);
  if (!proxies.length) throw new UserError('筛选后没有剩余节点，请检查包含 / 排除条件');

  const userinfo = sources.find((s) => s.userinfo)?.userinfo;

  if (opts.target === 'mixed') {
    const lines = generateLinks(proxies, warnings);
    return { body: encodeBase64(lines.join('\n')), nodeCount: lines.length, warnings, userinfo };
  }

  const header = [`由 sub-web 生成于 ${new Date().toISOString()}`];
  if (opts.list) {
    header.push(`节点 ${proxies.length} 个`, ...warnings.map((w) => `警告：${w}`));
    return { body: generateClash({ proxies, listOnly: true, header }), nodeCount: proxies.length, warnings, userinfo };
  }

  const groups = buildGroups(groupDefs, proxies.map((p) => p.name), warnings);
  const policies = new Set([...groups.map((g) => g.name), ...BUILTIN_POLICIES, ...proxies.map((p) => p.name)]);

  let rules;
  let providers;
  if (generateRules) {
    ({ rules, providers } = buildRules(cfg.rulesets, ruleLists, policies, opts, warnings));
    if (!cfg.overwriteOriginalRules && Array.isArray(base?.rules)) rules = [...base.rules, ...rules];
  } else if (Array.isArray(base?.rules)) {
    rules = base.rules;
  } else if (cfg.groups.length) {
    rules = [`MATCH,${groups[0].name}`];
  } else {
    rules = DEFAULT_RULES;
  }

  header.push(
    `节点 ${proxies.length} 个，策略组 ${groups.length} 个，规则 ${rules.length} 条`,
    ...warnings.map((w) => `警告：${w}`),
  );
  const body = generateClash({ proxies, groups, rules, providers, base: base || DEFAULT_CLASH_BASE, header });
  return { body, nodeCount: proxies.length, warnings, userinfo };
}

async function loadSources(opts, fetchText, warnings) {
  return Promise.all(
    opts.sources.map(async (src, i) => {
      const label = opts.sources.length > 1 ? `订阅 ${i + 1} ` : '订阅';
      if (!/^https?:\/\//i.test(src)) return { proxies: parseSubscription(src, warnings, label) };
      try {
        const { text, headers } = await fetchText(src, { ua: opts.ua, timeoutMs: 20000 });
        return { proxies: parseSubscription(text, warnings, label), userinfo: headers.get('subscription-userinfo') };
      } catch (e) {
        warnings.push(`${label}下载失败：${e.message}`);
        return { proxies: [] };
      }
    }),
  );
}

async function loadBase(url, fetchText, warnings) {
  try {
    const { text } = await fetchText(url, { cacheTtl: 3600 });
    const doc = YAML.parse(text, { uniqueKeys: false });
    if (doc && typeof doc === 'object' && !Array.isArray(doc)) return doc;
    warnings.push('clash_rule_base 不是有效的 YAML 对象，已使用默认基础配置');
  } catch (e) {
    warnings.push(`clash_rule_base 加载失败（${e.message}），已使用默认基础配置`);
  }
  return null;
}

async function loadRuleLists(rulesets, fetchText) {
  const urls = [...new Set(rulesets.filter((r) => r.url && /^https?:\/\//i.test(r.url)).map((r) => r.url))];
  const format = new Map(rulesets.filter((r) => r.url).map((r) => [r.url, r.format]));
  const entries = await Promise.all(
    urls.map(async (url) => {
      try {
        const { text } = await fetchText(url, { cacheTtl: 3600 });
        return [url, parseRuleList(text, format.get(url))];
      } catch (e) {
        return [url, { error: e.message }];
      }
    }),
  );
  return new Map(entries);
}

function buildRules(rulesets, ruleLists, policies, opts, warnings) {
  const collector = new RuleCollector();
  const providers = {};
  const providerByUrl = new Map();
  const usedNames = new Set();
  const unsupported = new Map();

  for (const rs of rulesets) {
    if (!policies.has(rs.group)) {
      warnings.push(`规则指向的策略组「${rs.group}」不存在，已跳过：${rs.inline ? `[]${rs.inline}` : rs.url}`);
      continue;
    }
    if (rs.inline) {
      const r = normalizeRule(rs.inline);
      if (r && !r.unsupported) collector.add(r, rs.group);
      else warnings.push(`无法识别的内联规则：[]${rs.inline}`);
      continue;
    }
    if (!/^https?:\/\//i.test(rs.url)) {
      warnings.push(`规则集只支持 http / https 地址，已跳过：${rs.url}`);
      continue;
    }
    if (!opts.expand) {
      let name = providerByUrl.get(rs.url);
      if (!name) {
        const built = buildProvider(rs, usedNames, opts.relay);
        name = built.name;
        providers[name] = built.provider;
        providerByUrl.set(rs.url, name);
      }
      collector.add({ type: 'RULE-SET', head: `RULE-SET,${name}`, tail: '', body: `RULE-SET,${name}` }, rs.group);
      continue;
    }
    const list = ruleLists.get(rs.url);
    if (!list || list.error) {
      warnings.push(`规则集下载失败（${list?.error || '未知错误'}）：${rs.url}`);
      continue;
    }
    for (const r of list.rules) collector.add(r, rs.group);
    for (const [type, n] of list.unsupported) unsupported.set(type, (unsupported.get(type) || 0) + n);
  }

  if (unsupported.size) {
    const summary = [...unsupported].map(([t, n]) => `${t}×${n}`).join('，');
    warnings.push(`已跳过 Clash 不支持的规则：${summary}`);
  }
  return { rules: collector.rules, providers };
}
