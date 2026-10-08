// 解析 subconverter 风格的外部配置（ini），例如仓库里的 clash.ini 或 ACL4SSR 在线配置。
// 支持的键：ruleset、custom_proxy_group、enable_rule_generator、overwrite_original_rules、
// clash_rule_base、exclude_remarks、include_remarks、rename、emoji、add_emoji、remove_old_emoji。

import { parseBool } from './utils.js';

const TEST_GROUP_TYPES = new Set(['url-test', 'fallback', 'load-balance']);

export function parseExternalConfig(text, warnings) {
  const cfg = {
    rulesets: [],
    groups: [],
    enableRuleGenerator: true,
    overwriteOriginalRules: true,
    clashRuleBase: null,
    excludeRemarks: [],
    includeRemarks: [],
    renames: [],
    emojis: [],
    addEmoji: null,
    removeOldEmoji: null,
  };
  const content = String(text || '').replace(/^\uFEFF/, '');
  if (/^\s*(proxy-groups|custom_proxy_group)\s*:/m.test(content) || /^\s*\[\[custom_groups\]\]/m.test(content)) {
    throw new Error('暂只支持 ini 格式的外部配置（YAML / TOML 外部配置不受支持）');
  }

  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith(';') || line.startsWith('#') || line.startsWith('//') || line.startsWith('[')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    switch (key) {
      case 'ruleset':
      case 'surge_ruleset': {
        const rs = parseRulesetLine(value);
        if (rs) cfg.rulesets.push(rs);
        else warnings.push(`无法解析 ruleset：${value}`);
        break;
      }
      case 'custom_proxy_group': {
        const g = parseGroupLine(value);
        if (g) cfg.groups.push(g);
        else warnings.push(`无法解析 custom_proxy_group：${value}`);
        break;
      }
      case 'enable_rule_generator':
        cfg.enableRuleGenerator = parseBool(value, true);
        break;
      case 'overwrite_original_rules':
        cfg.overwriteOriginalRules = parseBool(value, true);
        break;
      case 'clash_rule_base':
        cfg.clashRuleBase = value || null;
        break;
      case 'exclude_remarks':
        if (value) cfg.excludeRemarks.push(value);
        break;
      case 'include_remarks':
        if (value) cfg.includeRemarks.push(value);
        break;
      case 'rename': {
        const at = value.indexOf('@');
        if (at > 0) cfg.renames.push({ pattern: value.slice(0, at), replacement: value.slice(at + 1) });
        break;
      }
      case 'emoji': {
        const comma = value.lastIndexOf(',');
        if (comma > 0) cfg.emojis.push({ pattern: value.slice(0, comma), emoji: value.slice(comma + 1).trim() });
        break;
      }
      case 'add_emoji':
        cfg.addEmoji = parseBool(value, null);
        break;
      case 'remove_old_emoji':
        cfg.removeOldEmoji = parseBool(value, null);
        break;
      default:
        break;
    }
  }
  return cfg;
}

// ruleset=策略组,URL[,更新间隔] 或 ruleset=策略组,[]GEOIP,CN / []FINAL
// URL 可带 clash-domain: / clash-ipcidr: / clash-classic: 等类型前缀。
export function parseRulesetLine(value) {
  const comma = value.indexOf(',');
  if (comma <= 0) return null;
  const group = value.slice(0, comma).trim();
  let source = value.slice(comma + 1).trim();
  if (!group || !source) return null;
  if (source.startsWith('[]')) return { group, inline: source.slice(2).trim() };

  let interval;
  const intervalMatch = source.match(/^(.*\S),\s*(\d+)$/);
  if (intervalMatch) {
    source = intervalMatch[1];
    interval = Number(intervalMatch[2]);
  }
  let format;
  const prefix = source.match(/^(clash-domain|clash-ipcidr|clash-classic|surge|quanx):(.*)$/i);
  if (prefix) {
    format = prefix[1].toLowerCase();
    source = prefix[2].trim();
  }
  return { group, url: source, format, interval };
}

// 名称`类型`成员1`成员2...；测速类分组末尾为 `测速地址`间隔[,超时][,容差]
export function parseGroupLine(value) {
  const parts = value.split('`');
  if (parts.length < 2) return null;
  const name = parts[0].trim();
  const type = parts[1].trim().toLowerCase();
  if (!name || !type) return null;
  let items = parts.slice(2);
  const group = { name, type, items: [] };
  if (TEST_GROUP_TYPES.has(type)) {
    const urlIdx = items.findIndex((it) => /^https?:\/\//i.test(it.trim()));
    if (urlIdx >= 0) {
      group.url = items[urlIdx].trim();
      const [interval, timeout, tolerance] = (items[urlIdx + 1] || '').split(',').map((s) => s.trim());
      if (interval) group.interval = Number(interval);
      if (timeout) group.timeout = Number(timeout);
      if (tolerance) group.tolerance = Number(tolerance);
      items = items.slice(0, urlIdx);
    }
  }
  group.items = items.map((s) => s.trim()).filter(Boolean);
  return group;
}
