// 规则集处理：把 Surge / Clash 文本列表或 Clash payload YAML 转成 mihomo 规则，
// 或者在不展开时生成 rule-providers，由客户端自行下载规则集。

import { decodeFragment } from './utils.js';

// mihomo 支持的规则类型
const SUPPORTED = new Set([
  'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'DOMAIN-WILDCARD', 'GEOSITE',
  'IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN', 'GEOIP',
  'SRC-GEOIP', 'SRC-IP-ASN', 'SRC-IP-CIDR', 'SRC-IP-SUFFIX',
  'DST-PORT', 'SRC-PORT', 'IN-PORT', 'IN-TYPE', 'IN-USER', 'IN-NAME',
  'PROCESS-NAME', 'PROCESS-PATH', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX', 'PROCESS-NAME-WILDCARD',
  'NETWORK', 'UID', 'DSCP', 'RULE-SET', 'SUB-RULE', 'MATCH',
]);
const LOGIC = new Set(['AND', 'OR', 'NOT']);
// 其他客户端写法到 mihomo 写法
const ALIASES = {
  FINAL: 'MATCH',
  'DEST-PORT': 'DST-PORT',
  'SRC-IP': 'SRC-IP-CIDR',
  'IP6-CIDR': 'IP-CIDR6',
  HOST: 'DOMAIN',
  'HOST-SUFFIX': 'DOMAIN-SUFFIX',
  'HOST-KEYWORD': 'DOMAIN-KEYWORD',
  'HOST-WILDCARD': 'DOMAIN-WILDCARD',
};
// 规则末尾允许保留的附加参数
const RULE_OPTIONS = new Set(['no-resolve', 'src']);

const CIDR_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)(?:\/\d{1,3})?$/;

// 把一行规则拆成 head（匹配条件）与 tail（no-resolve 等选项），策略组插在两者之间，
// 如 "IP-CIDR,1.0.0.0/8" + ",no-resolve"。body = head + tail，作为去重键。
// 返回 null 表示空行或注释；规则集动辄上万行，这里尽量避免正则和多余的数组操作。
function rule(type, head, tail = '') {
  return { type, head, tail, body: head + tail };
}

export function normalizeRule(raw, format) {
  let line = raw.trim();
  if (!line) return null;
  const first = line[0];
  if (first === '#' || first === ';' || line.startsWith('//')) return null;
  if (first === '-') {
    line = line.slice(1).trim();
    const q = line[0];
    if ((q === "'" || q === '"') && line.endsWith(q)) line = line.slice(1, -1).trim();
    if (!line) return null;
  } else if (first === 'p' && /^payload\s*:/.test(line)) {
    return null;
  }

  const comma = line.indexOf(',');
  if (comma < 0) {
    const upper = line.toUpperCase();
    if (upper === 'MATCH' || upper === 'FINAL') return rule('MATCH', 'MATCH');
    if (format === 'clash-ipcidr' || CIDR_RE.test(line)) {
      return rule('IP-CIDR', `${line.includes(':') ? 'IP-CIDR6' : 'IP-CIDR'},${line}`);
    }
    if (line.startsWith('+.')) return rule('DOMAIN-SUFFIX', `DOMAIN-SUFFIX,${line.slice(2)}`);
    if (first === '.') return rule('DOMAIN-SUFFIX', `DOMAIN-SUFFIX,${line.slice(1)}`);
    if (line.includes('*')) return rule('DOMAIN-WILDCARD', `DOMAIN-WILDCARD,${line}`);
    // Surge DOMAIN-SET 与 Clash domain 列表里，不带前缀的域名都表示精确匹配
    return rule('DOMAIN', `DOMAIN,${line}`);
  }

  let type = line.slice(0, comma).trim().toUpperCase();
  type = ALIASES[type] || type;
  if (LOGIC.has(type)) return normalizeLogic(type, line.slice(comma + 1).trim());
  if (!SUPPORTED.has(type)) return { unsupported: type };
  if (type === 'MATCH') return rule('MATCH', 'MATCH');

  const next = line.indexOf(',', comma + 1);
  const value = (next < 0 ? line.slice(comma + 1) : line.slice(comma + 1, next)).trim();
  if (!value) return null;
  let tail = '';
  if (next >= 0) {
    // 列表中偶尔带有策略名，丢弃，只保留 no-resolve 等选项
    for (const part of line.slice(next + 1).split(',')) {
      const opt = part.trim().toLowerCase();
      if (RULE_OPTIONS.has(opt)) tail += `,${opt}`;
    }
  }
  return rule(type, `${type},${value}`, tail);
}

// AND / OR / NOT 逻辑规则：AND,((DOMAIN,a.com),(NETWORK,UDP))[,策略]。
// 只保留括号内的部分（列表里可能自带策略名），并把子规则的类型按别名表转换；
// 任一子规则是 mihomo 不支持的类型，整条按不支持处理，否则 mihomo 会拒绝加载整个配置。
function normalizeLogic(type, rest) {
  if (!rest.startsWith('(')) return null;
  let depth = 0;
  let end = -1;
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '(') depth++;
    else if (rest[i] === ')' && --depth === 0) {
      end = i;
      break;
    }
  }
  if (end < 0) return null;
  let unsupported = null;
  const inner = rest.slice(0, end + 1).replace(/\(\s*([A-Za-z0-9-]+)\s*,/g, (_, t) => {
    let sub = t.toUpperCase();
    sub = ALIASES[sub] || sub;
    if (!LOGIC.has(sub) && !SUPPORTED.has(sub)) unsupported = sub;
    return `(${sub},`;
  });
  if (unsupported) return { unsupported };
  return rule(type, `${type},${inner}`);
}

export function attachGroup(r, group) {
  return `${r.head},${group}${r.tail}`;
}

// 规则列表里出现这些类型没有意义：MATCH 会让后面的规则全部失效，
// RULE-SET / SUB-RULE 指向的 provider 在生成的配置里并不存在。
const LIST_FORBIDDEN = new Set(['MATCH', 'RULE-SET', 'SUB-RULE']);

export function parseRuleList(text, format) {
  const rules = [];
  const unsupported = new Map();
  for (const raw of String(text).replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const r = normalizeRule(raw, format);
    if (!r) continue;
    const bad = r.unsupported || (LIST_FORBIDDEN.has(r.type) ? r.type : null);
    if (bad) unsupported.set(bad, (unsupported.get(bad) || 0) + 1);
    else rules.push(r);
  }
  return { rules, unsupported };
}

// 按顺序展开规则；匹配条件完全相同的后续规则永远不会命中，直接去重。
export class RuleCollector {
  constructor() {
    this.rules = [];
    this.seen = new Set();
  }

  add(r, group) {
    if (this.seen.has(r.body)) return;
    this.seen.add(r.body);
    this.rules.push(attachGroup(r, group));
  }
}

// 为 expand=false 生成 rule-providers 条目。下载地址指向本站 /ruleset，
// 由它把各种格式的规则集统一转换为 classical 文本。
export function buildProvider(ruleset, usedNames, relay) {
  const file = decodeFragment(ruleset.url.split(/[?#]/)[0].split('/').pop() || 'ruleset');
  const stem = file.replace(/\.[^.]+$/, '').replace(/[^\w\u4e00-\u9fa5-]+/g, '_') || 'ruleset';
  let name = stem;
  for (let i = 2; usedNames.has(name); i++) name = `${stem}_${i}`;
  usedNames.add(name);

  const params = new URLSearchParams({ url: ruleset.url });
  if (ruleset.format?.startsWith('clash-')) params.set('type', ruleset.format);
  if (relay.token) params.set('token', relay.token);
  return {
    name,
    provider: {
      type: 'http',
      behavior: 'classical',
      format: 'text',
      url: `${relay.origin}/ruleset?${params}`,
      interval: ruleset.interval || 86400,
    },
  };
}
