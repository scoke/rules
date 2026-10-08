// 节点后处理：筛选、重命名、类型前缀、Emoji、排序、去重，以及 udp / tfo / scv 覆盖。

import { addEmoji, removeEmoji } from './emoji.js';
import { compileRegex } from './utils.js';

const TLS_TYPES = new Set(['vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'http', 'socks5']);
const TYPE_LABELS = {
  ss: 'SS', ssr: 'SSR', vmess: 'VMess', vless: 'VLESS', trojan: 'Trojan', hysteria: 'Hysteria',
  hysteria2: 'Hysteria2', tuic: 'TUIC', anytls: 'AnyTLS', socks5: 'SOCKS5', http: 'HTTP',
  wireguard: 'WireGuard', snell: 'Snell',
};

export function processNodes(proxies, opts, cfg, reservedNames, warnings) {
  const excludes = [...cfg.excludeRemarks, opts.exclude]
    .filter(Boolean)
    .map((p) => compileRegex(p, warnings, '排除节点的正则'))
    .filter(Boolean);
  const includes = [...cfg.includeRemarks, opts.include]
    .filter(Boolean)
    .map((p) => compileRegex(p, warnings, '保留节点的正则'))
    .filter(Boolean);
  let list = proxies.filter(
    (p) => !excludes.some((re) => re.test(p.name)) && (includes.length === 0 || includes.some((re) => re.test(p.name))),
  );

  const renames = [...cfg.renames, ...opts.renames]
    .map((r) => ({ re: compileRegex(r.pattern, warnings, '重命名规则', 'g'), replacement: r.replacement }))
    .filter((r) => r.re);
  const emojiRules = cfg.emojis
    .map((e) => ({ regex: compileRegex(e.pattern, warnings, 'Emoji 规则'), emoji: e.emoji }))
    .filter((e) => e.regex);
  const wantEmoji = opts.emoji ?? cfg.addEmoji ?? true;
  const dropOldEmoji = opts.emoji ?? cfg.removeOldEmoji ?? true;

  list = list.map((p) => {
    let name = String(p.name).trim();
    for (const r of renames) name = name.replace(r.re, r.replacement);
    if (opts.appendType) name = `[${TYPE_LABELS[p.type] || p.type}] ${name}`;
    if (dropOldEmoji) name = removeEmoji(name);
    if (wantEmoji) name = addEmoji(name, emojiRules);
    return { ...p, name: name.trim() || `${p.type}-${p.server}` };
  });

  if (opts.sort) list.sort((a, b) => a.name.localeCompare(b.name, 'zh-Hans-CN'));

  const used = new Set(reservedNames);
  for (const p of list) {
    let name = p.name;
    for (let i = 2; used.has(name); i++) name = `${p.name} ${i}`;
    used.add(name);
    p.name = name;
    if (opts.udp !== undefined) p.udp = opts.udp;
    if (opts.tfo !== undefined) p.tfo = opts.tfo;
    if (opts.scv !== undefined && TLS_TYPES.has(p.type)) p['skip-cert-verify'] = opts.scv;
  }
  return list;
}
