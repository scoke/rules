// 通用工具：Base64（兼容 URL-safe 与缺失填充）、URL 解码、主机端口拆分等。

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

export function decodeBase64(input) {
  let s = String(input).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  s = s.replace(/=+$/, '');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return textDecoder.decode(bytes);
}

// 仅在内容看起来像 Base64 时尝试解码，失败返回 null。
export function tryDecodeBase64(input) {
  const s = String(input).trim();
  if (!s || !/^[A-Za-z0-9+/=_\-\s]+$/.test(s)) return null;
  try {
    return decodeBase64(s);
  } catch {
    return null;
  }
}

export function encodeBase64(str, urlSafe = false) {
  const bytes = textEncoder.encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  const out = btoa(bin);
  return urlSafe ? out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : out;
}

// mihomo 的 YAML 解析器按 YAML 1.1 把 U+0085、U+2028、U+2029 也当作换行，而 JS 和 yaml 库不会。
// 订阅内容里藏有这些字符时，注释或普通标量会在 mihomo 眼里提前结束，后面的文字变成配置的顶层键。
// 因此所有来自外部的文本在进入流水线前都把它们（连同其他控制字符）替换成空格，保留 \t \r \n。
const UNSAFE_TEXT = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029\ufeff]/g;

export function sanitizeText(s) {
  return String(s).replace(UNSAFE_TEXT, ' ');
}

// 递归处理对象中的全部字符串（含键名），用于最终输出前兜底。
export function sanitizeDeep(value) {
  if (typeof value === 'string') return sanitizeText(value);
  if (Array.isArray(value)) return value.map(sanitizeDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[sanitizeText(k)] = sanitizeDeep(v);
    return out;
  }
  return value;
}

// 只解百分号编码，保留字面量 "+"（节点名、密码里常见）。
export function decodeFragment(s) {
  if (!s) return '';
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// 拆分 host:port，支持 [IPv6]:port 与 Hysteria2 的多端口写法 host:443,20000-30000。
export function splitHostPort(hostport) {
  const s = String(hostport).trim().replace(/\/+$/, '');
  const m = s.match(/^\[([^\]]+)\]:([\d,\-]+)$/) || s.match(/^([^:\[\]]+):([\d,\-]+)$/);
  if (!m) throw new Error(`无法解析地址 ${s}`);
  const portSpec = m[2];
  const port = Number(portSpec.match(/^\d+/)?.[0]);
  if (!port || port > 65535) throw new Error(`端口无效 ${portSpec}`);
  return { server: m[1], port, portSpec };
}

// 解析 scheme://userinfo@host:port/path?query#fragment 形式的节点链接。
// 不用 URL 类：它会把非特殊协议的主机名原样保留、并吞掉默认端口，行为不稳定。
export function parseStdUri(uri) {
  const schemeEnd = uri.indexOf('://');
  if (schemeEnd < 0) throw new Error('缺少协议头');
  const scheme = uri.slice(0, schemeEnd).toLowerCase();
  let rest = uri.slice(schemeEnd + 3);
  let name = '';
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) {
    name = decodeFragment(rest.slice(hashIdx + 1));
    rest = rest.slice(0, hashIdx);
  }
  let query = '';
  const qIdx = rest.indexOf('?');
  if (qIdx >= 0) {
    query = rest.slice(qIdx + 1);
    rest = rest.slice(0, qIdx);
  }
  let path = '';
  const slashIdx = rest.indexOf('/', rest.lastIndexOf('@') + 1);
  if (slashIdx >= 0) {
    path = rest.slice(slashIdx);
    rest = rest.slice(0, slashIdx);
  }
  const atIdx = rest.lastIndexOf('@');
  const userinfo = atIdx >= 0 ? rest.slice(0, atIdx) : '';
  const hostport = atIdx >= 0 ? rest.slice(atIdx + 1) : rest;
  const { server, port, portSpec } = splitHostPort(hostport);
  return {
    scheme,
    userinfo: decodeFragment(userinfo),
    rawUserinfo: userinfo,
    server,
    port,
    portSpec,
    path,
    params: new QueryParams(query),
    name,
  };
}

// 与 URLSearchParams 不同：不把 "+" 当作空格（密码、公钥里常含 "+"），键名大小写不敏感兜底。
export class QueryParams {
  constructor(query = '') {
    this.map = new Map();
    for (const part of String(query).split('&')) {
      if (!part) continue;
      const eq = part.indexOf('=');
      const key = decodeFragment(eq >= 0 ? part.slice(0, eq) : part);
      const value = decodeFragment(eq >= 0 ? part.slice(eq + 1) : '');
      if (!this.map.has(key)) this.map.set(key, value);
    }
  }

  get(key) {
    if (this.map.has(key)) return this.map.get(key);
    const lower = key.toLowerCase();
    for (const [k, v] of this.map) if (k.toLowerCase() === lower) return v;
    return null;
  }

  has(key) {
    return this.get(key) !== null;
  }
}

export function parseBool(value, fallback) {
  if (value == null || value === '') return fallback;
  const v = String(value).toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  return fallback;
}

export function splitList(value, sep = ',') {
  if (!value) return [];
  return String(value)
    .split(sep)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function formatHost(server) {
  return server.includes(':') ? `[${server}]` : server;
}

// 兼容 subconverter 配置里常见的 (?i) 前缀写法（JS 不支持全局内联修饰符）。
export function compileRegex(pattern, warnings, what = '正则', flags = '') {
  let source = String(pattern);
  if (source.startsWith('(?i)')) {
    source = source.slice(4);
    if (!flags.includes('i')) flags += 'i';
  }
  try {
    return new RegExp(source, flags);
  } catch {
    warnings?.push(`${what}无效，已忽略：${pattern}`);
    return null;
  }
}
