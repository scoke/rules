// 根据 custom_proxy_group 定义生成 mihomo 的 proxy-groups。
// 成员写法：[]名称 引用策略组或内置策略；其他内容视为正则，按节点名匹配。

import { compileRegex } from './utils.js';

export const BUILTIN_POLICIES = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE']);
export const TEST_TYPES = new Set(['url-test', 'fallback', 'load-balance']);
const KNOWN_TYPES = new Set(['select', 'relay', ...TEST_TYPES]);
const DEFAULT_TEST_URL = 'http://www.gstatic.com/generate_204';

export const DEFAULT_GROUP_DEFS = [
  { name: '🚀 节点选择', type: 'select', items: ['[]♻️ 自动选择', '[]DIRECT', '.*'] },
  { name: '♻️ 自动选择', type: 'url-test', items: ['.*'], url: DEFAULT_TEST_URL, interval: 300, tolerance: 50 },
];
export const DEFAULT_RULES = ['GEOIP,LAN,DIRECT,no-resolve', 'GEOIP,CN,DIRECT', 'MATCH,🚀 节点选择'];

export function buildGroups(defs, nodeNames, warnings) {
  const groupNames = new Set(defs.map((d) => d.name));
  const nodeSet = new Set(nodeNames);
  const groups = defs.map((def) => {
    const members = new Set();
    for (const item of def.items) {
      if (item.startsWith('[]')) {
        const ref = item.slice(2).trim();
        if (ref === def.name) continue;
        const builtin = ref.toUpperCase();
        if (BUILTIN_POLICIES.has(builtin)) members.add(builtin);
        else if (groupNames.has(ref) || nodeSet.has(ref)) members.add(ref);
        else warnings.push(`策略组「${def.name}」引用的「${ref}」不存在，已忽略`);
      } else if (item.startsWith('!!')) {
        warnings.push(`策略组「${def.name}」中的 ${item.split('=')[0]} 写法暂不支持，已忽略`);
      } else {
        const re = compileRegex(item, warnings, `策略组「${def.name}」的正则`);
        if (!re) continue;
        for (const name of nodeNames) if (re.test(name)) members.add(name);
      }
    }

    let type = def.type;
    if (!KNOWN_TYPES.has(type)) {
      warnings.push(`策略组「${def.name}」的类型 ${type} 不受 Clash 支持，已改为 select`);
      type = 'select';
    }
    const group = { name: def.name, type, proxies: [...members] };
    if (TEST_TYPES.has(type)) {
      group.url = def.url || DEFAULT_TEST_URL;
      group.interval = def.interval || 300;
      // subconverter 配置里的超时以秒为单位，mihomo 以毫秒为单位
      if (def.timeout) group.timeout = def.timeout < 1000 ? def.timeout * 1000 : def.timeout;
      if (def.tolerance && type === 'url-test') group.tolerance = def.tolerance;
    }
    return group;
  });

  breakCycles(groups, warnings);
  for (const g of groups) {
    if (g.proxies.length === 0) g.proxies = ['DIRECT'];
  }
  return groups;
}

// mihomo 加载配置时会检测策略组循环引用并直接报错，这里按深度优先删掉形成回路的那条引用。
function breakCycles(groups, warnings) {
  const byName = new Map(groups.map((g) => [g.name, g]));
  const state = new Map();
  const visit = (group) => {
    state.set(group.name, 'visiting');
    group.proxies = group.proxies.filter((ref) => {
      const child = byName.get(ref);
      if (!child) return true;
      const s = state.get(ref);
      if (s === 'visiting') {
        warnings.push(`策略组「${group.name}」引用「${ref}」会形成循环（Clash 会报 loop detected），已移除该引用`);
        return false;
      }
      if (!s) visit(child);
      return true;
    });
    state.set(group.name, 'done');
  };
  for (const g of groups) if (!state.has(g.name)) visit(g);
}
