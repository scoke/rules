// 识别订阅内容格式并解析出节点：Clash/mihomo YAML、Base64 链接列表、明文链接列表、SIP008 JSON。

import YAML from 'yaml';
import { parseLink } from './links.js';
import { tryDecodeBase64 } from '../utils.js';

export function parseSubscription(input, warnings, label = '订阅') {
  let text = String(input || '').replace(/^\uFEFF/, '').trim();
  if (!text) {
    warnings.push(`${label}内容为空`);
    return [];
  }

  if (!text.includes('://')) {
    const decoded = tryDecodeBase64(text);
    if (decoded && (decoded.includes('://') || /^\s*proxies\s*:/m.test(decoded))) {
      text = decoded.replace(/^\uFEFF/, '').trim();
    }
  }

  if (/^\s*proxies\s*:/m.test(text)) return parseClashYaml(text, warnings, label);
  if (text.startsWith('{')) return parseJson(text, warnings, label);
  return parseLinks(text, warnings, label);
}

function parseClashYaml(text, warnings, label) {
  let doc;
  try {
    doc = YAML.parse(text, { maxAliasCount: -1, uniqueKeys: false });
  } catch (e) {
    warnings.push(`${label} YAML 解析失败：${e.message.split('\n')[0]}`);
    return [];
  }
  const list = Array.isArray(doc?.proxies) ? doc.proxies : [];
  const proxies = [];
  for (const p of list) {
    if (p && typeof p === 'object' && p.name != null && p.type && p.server && p.port) {
      proxies.push({ ...p, name: String(p.name), port: Number(p.port) });
    }
  }
  if (list.length !== proxies.length) {
    warnings.push(`${label}中有 ${list.length - proxies.length} 个节点缺少必要字段，已跳过`);
  }
  return proxies;
}

function parseJson(text, warnings, label) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    warnings.push(`${label}不是有效的 JSON`);
    return [];
  }
  // SIP008：{ "servers": [{ server, server_port, password, method, remarks }] }
  if (Array.isArray(doc.servers)) {
    return doc.servers
      .filter((s) => s.server && s.server_port)
      .map((s) => ({
        name: String(s.remarks || `${s.server}:${s.server_port}`),
        type: 'ss',
        server: s.server,
        port: Number(s.server_port),
        cipher: s.method,
        password: s.password,
      }));
  }
  warnings.push(`${label}是暂不支持的 JSON 格式`);
  return [];
}

function parseLinks(text, warnings, label) {
  const proxies = [];
  let unknown = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    try {
      const proxy = parseLink(line);
      if (proxy) proxies.push(proxy);
      else unknown++;
    } catch (e) {
      const scheme = line.split('://')[0];
      const name = line.includes('#') ? decodeName(line.slice(line.lastIndexOf('#') + 1)) : '';
      warnings.push(`${label}中的 ${scheme} 节点${name ? `「${name}」` : ''}解析失败：${e.message}`);
    }
  }
  if (unknown) warnings.push(`${label}中有 ${unknown} 行无法识别，已跳过`);
  return proxies;
}

function decodeName(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
