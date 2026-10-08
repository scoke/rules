// 生成 Clash（mihomo）YAML 配置。

import YAML from 'yaml';
import { sanitizeDeep, sanitizeText } from '../utils.js';

export const DEFAULT_CLASH_BASE = {
  'mixed-port': 7890,
  'allow-lan': false,
  mode: 'rule',
  'log-level': 'info',
  'external-controller': '127.0.0.1:9090',
  'unified-delay': true,
  'tcp-concurrent': true,
};

// 放在 name/type/server/port 之后的字段按原顺序输出，便于阅读
const LEADING_KEYS = ['name', 'type', 'server', 'port'];

function orderProxy(p) {
  const out = {};
  for (const k of LEADING_KEYS) if (p[k] !== undefined) out[k] = p[k];
  for (const [k, v] of Object.entries(p)) if (!(k in out)) out[k] = v;
  return out;
}

// 按 YAML 1.1 规则决定是否加引号，避免 yes/on/0755 之类的字符串被 Clash 当作布尔或数字。
function dump(doc) {
  return YAML.stringify(doc, { version: '1.1', lineWidth: 0, aliasDuplicateObjects: false });
}

// 规则动辄上万条，逐行拼接比经过 YAML AST 快一个数量级；无法安全写成普通标量的规则改用双引号。
const PLAIN_RULE = /^[A-Za-z][A-Za-z0-9-]*,/;
const UNSAFE_PLAIN = /: | #|:$|\s$|[\u0000-\u001f\u007f\u0085\u2028\u2029\ufeff]/;

function ruleScalar(rule) {
  const s = String(rule);
  if (PLAIN_RULE.test(s) && !UNSAFE_PLAIN.test(s)) return s;
  return JSON.stringify(s).replace(/[\u0085\u2028\u2029\ufeff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function dumpRules(rules) {
  if (!rules.length) return 'rules: []\n';
  let out = 'rules:\n';
  for (const r of rules) out += `  - ${ruleScalar(r)}\n`;
  return out;
}

// 注释里带有警告原文（含订阅里的节点名），必须去掉所有换行和控制字符，否则会被 mihomo 当作新的一行。
export function renderHeader(lines) {
  return lines.map((l) => `# ${sanitizeText(String(l).replace(/[\r\n\t]+/g, ' '))}`).join('\n') + '\n';
}

// yaml 库不会给含 U+2028 / U+2029 的字符串加引号，输出前再统一清理一遍。
export function generateClash({ proxies, groups, rules, providers, base, listOnly, header }) {
  const ordered = proxies.map(orderProxy);
  if (listOnly) return renderHeader(header) + dump(sanitizeDeep({ proxies: ordered }));

  const doc = { ...(base || DEFAULT_CLASH_BASE) };
  for (const k of ['proxies', 'proxy-groups', 'rule-providers', 'rules']) delete doc[k];
  doc.proxies = ordered;
  doc['proxy-groups'] = groups;
  if (providers && Object.keys(providers).length) {
    doc['rule-providers'] = { ...(base?.['rule-providers'] || {}), ...providers };
  } else if (base?.['rule-providers']) {
    doc['rule-providers'] = base['rule-providers'];
  }
  return renderHeader(header) + dump(sanitizeDeep(doc)) + dumpRules(rules);
}
