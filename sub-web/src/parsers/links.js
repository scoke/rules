// 把分享链接解析为 Clash（mihomo）代理对象。内部统一使用 mihomo 的字段命名，
// 这样 Clash YAML 订阅里的节点可以原样沿用，输出其他格式时再反向转换。

import {
  decodeBase64,
  decodeFragment,
  parseStdUri,
  QueryParams,
  splitHostPort,
  splitList,
  parseBool,
} from '../utils.js';

const PARSERS = {
  ss: parseSS,
  ssr: parseSSR,
  vmess: parseVmess,
  vless: parseVless,
  trojan: parseTrojan,
  hysteria2: parseHysteria2,
  hy2: parseHysteria2,
  hysteria: parseHysteria,
  tuic: parseTuic,
  anytls: parseAnyTLS,
  socks: parseSocks,
  socks5: parseSocks,
  wireguard: parseWireGuard,
  wg: parseWireGuard,
};

export const SUPPORTED_SCHEMES = Object.keys(PARSERS);

// 解析单条分享链接；无法识别返回 null，格式错误抛出异常。
export function parseLink(line) {
  const link = line.trim();
  const m = link.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
  if (!m) return null;
  const parser = PARSERS[m[1].toLowerCase()];
  if (!parser) return null;
  const proxy = parser(link);
  if (!proxy.name) proxy.name = `${proxy.type}-${proxy.server}:${proxy.port}`;
  return proxy;
}

function base(name, type, server, port) {
  return { name: name.trim(), type, server, port };
}

function flag(params, ...keys) {
  for (const k of keys) {
    const v = params.get(k);
    if (v != null && v !== '') return parseBool(v, false);
  }
  return undefined;
}

function first(params, ...keys) {
  for (const k of keys) {
    const v = params.get(k);
    if (v != null && v !== '') return v;
  }
  return undefined;
}

// 去掉值为 undefined / 空字符串 / 空数组 / 空对象的字段，保持输出整洁。
export function prune(obj) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || v === '') delete obj[k];
    else if (Array.isArray(v) && v.length === 0) delete obj[k];
    else if (typeof v === 'object' && !Array.isArray(v)) {
      prune(v);
      if (Object.keys(v).length === 0) delete obj[k];
    }
  }
  return obj;
}

// ---------- Shadowsocks ----------

function parseSS(link) {
  let body = link.slice('ss://'.length);
  let name = '';
  const hashIdx = body.indexOf('#');
  if (hashIdx >= 0) {
    name = decodeFragment(body.slice(hashIdx + 1));
    body = body.slice(0, hashIdx);
  }
  let query = '';
  const qIdx = body.indexOf('?');
  if (qIdx >= 0) {
    query = body.slice(qIdx + 1);
    body = body.slice(0, qIdx);
  }
  body = body.replace(/\/+$/, '');
  // 旧格式：ss://BASE64(method:password@host:port)
  if (!body.includes('@')) body = decodeBase64(body);
  const at = body.lastIndexOf('@');
  if (at < 0) throw new Error('SS 链接缺少 @');
  let userinfo = decodeFragment(body.slice(0, at));
  if (!userinfo.includes(':')) userinfo = decodeBase64(userinfo);
  const colon = userinfo.indexOf(':');
  const cipher = userinfo.slice(0, colon);
  const password = userinfo.slice(colon + 1);
  const { server, port } = splitHostPort(body.slice(at + 1));
  const proxy = { ...base(name, 'ss', server, port), cipher, password };

  const params = new QueryParams(query);
  const plugin = params.get('plugin');
  if (plugin) applySSPlugin(proxy, plugin);
  if (flag(params, 'uot', 'udp-over-tcp')) proxy['udp-over-tcp'] = true;
  return proxy;
}

function applySSPlugin(proxy, pluginStr) {
  const [pluginName, ...rawOpts] = pluginStr.split(';');
  const opts = {};
  for (const o of rawOpts) {
    const eq = o.indexOf('=');
    if (eq >= 0) opts[o.slice(0, eq)] = o.slice(eq + 1);
    else if (o) opts[o] = true;
  }
  if (pluginName === 'obfs-local' || pluginName === 'simple-obfs') {
    proxy.plugin = 'obfs';
    proxy['plugin-opts'] = prune({ mode: opts.obfs, host: opts['obfs-host'] });
  } else if (pluginName === 'v2ray-plugin') {
    proxy.plugin = 'v2ray-plugin';
    proxy['plugin-opts'] = prune({
      mode: opts.mode || 'websocket',
      host: opts.host,
      path: opts.path,
      tls: opts.tls === true || opts.tls === 'true' ? true : undefined,
      mux: opts.mux === undefined ? undefined : opts.mux !== 'false' && opts.mux !== '0',
    });
  } else if (pluginName === 'shadow-tls') {
    proxy.plugin = 'shadow-tls';
    proxy['plugin-opts'] = prune({
      host: opts.host,
      password: opts.password,
      version: opts.version ? Number(opts.version) : undefined,
    });
  } else {
    throw new Error(`不支持的 SS 插件 ${pluginName}`);
  }
}

// ---------- ShadowsocksR ----------

function parseSSR(link) {
  const decoded = decodeBase64(link.slice('ssr://'.length));
  const [main, query = ''] = decoded.split('/?');
  // host 可能是 IPv6，因此从右往左取固定字段
  const parts = main.split(':');
  if (parts.length < 6) throw new Error('SSR 链接字段不足');
  const password = decodeBase64(parts.pop());
  const obfs = parts.pop();
  const cipher = parts.pop();
  const protocol = parts.pop();
  const port = Number(parts.pop());
  const server = parts.join(':');
  const params = new QueryParams(query);
  const b64 = (k) => {
    const v = params.get(k);
    return v ? decodeBase64(v) : undefined;
  };
  return prune({
    ...base(b64('remarks') || '', 'ssr', server, port),
    cipher: cipher === 'none' ? 'dummy' : cipher,
    password,
    obfs,
    protocol,
    'obfs-param': b64('obfsparam'),
    'protocol-param': b64('protoparam'),
  });
}

// ---------- 传输层与 TLS（VMess / VLESS / Trojan 共用） ----------

function applyTransport(proxy, { network, host, path, serviceName, headerType, mode, extra }) {
  const net = (network || 'tcp').toLowerCase();
  if (net === 'tcp' || net === 'raw') {
    if (headerType === 'http') {
      proxy.network = 'http';
      proxy['http-opts'] = prune({
        method: 'GET',
        path: splitList(path || '/'),
        headers: host ? { Host: splitList(host) } : undefined,
      });
    }
    return;
  }
  if (net === 'ws' || net === 'websocket' || net === 'httpupgrade') {
    proxy.network = 'ws';
    const opts = { path: path || '/', headers: host ? { Host: host } : undefined };
    if (net === 'httpupgrade') opts['v2ray-http-upgrade'] = true;
    proxy['ws-opts'] = prune(opts);
    return;
  }
  if (net === 'grpc') {
    proxy.network = 'grpc';
    proxy['grpc-opts'] = prune({ 'grpc-service-name': serviceName || path });
    return;
  }
  if (net === 'h2' || net === 'http') {
    proxy.network = 'h2';
    proxy['h2-opts'] = prune({ host: splitList(host), path: path || '/' });
    return;
  }
  if (net === 'xhttp' || net === 'splithttp') {
    proxy.network = 'xhttp';
    proxy['xhttp-opts'] = prune({ path: path || '/', host, mode, ...extra });
    return;
  }
  throw new Error(`Clash 不支持的传输方式 ${net}`);
}

function applyTls(proxy, { sni, alpn, fp, insecure, sniKey = 'servername' }) {
  if (sni) proxy[sniKey] = sni;
  const alpnList = splitList(alpn);
  if (alpnList.length) proxy.alpn = alpnList;
  if (fp && fp !== 'none') proxy['client-fingerprint'] = fp;
  if (insecure) proxy['skip-cert-verify'] = true;
}

// ---------- VMess ----------

function parseVmess(link) {
  const body = link.slice('vmess://'.length);
  // Xray 新式标准链接：vmess://uuid@host:port?type=ws...
  // Base64 字符集里没有 "@"，可以据此区分两种格式。
  if (body.split(/[?#]/)[0].includes('@')) {
    return parseVmessStd(link);
  }
  const [b64Part, query] = body.split('?');
  const decoded = decodeBase64(b64Part.split('#')[0]);
  if (!decoded.trim().startsWith('{')) return parseVmessShadowrocket(decoded, query || '');
  const j = JSON.parse(decoded);
  const proxy = {
    ...base(String(j.ps || ''), 'vmess', String(j.add), Number(j.port)),
    uuid: j.id,
    alterId: Number(j.aid || 0),
    cipher: j.scy || 'auto',
  };
  const tls = j.tls === 'tls' || j.tls === true || j.tls === 'reality';
  if (tls) {
    proxy.tls = true;
    applyTls(proxy, {
      sni: j.sni || j.host,
      alpn: j.alpn,
      fp: j.fp,
      insecure: parseBool(j.allowInsecure ?? j.skip_cert_verify, false),
    });
  }
  const net = j.net || 'tcp';
  applyTransport(proxy, {
    network: net,
    host: j.host,
    path: j.path,
    serviceName: net === 'grpc' ? j.path : undefined,
    headerType: j.type,
    mode: net === 'xhttp' ? j.type : undefined,
  });
  return prune(proxy);
}

function parseVmessShadowrocket(decoded, query) {
  // Shadowrocket：BASE64(cipher:uuid@host:port)?remarks=..&obfs=websocket&path=..&tls=1
  const m = decoded.match(/^([^:]+):([^@]+)@(.+)$/);
  if (!m) throw new Error('无法识别的 VMess 链接');
  const { server, port } = splitHostPort(m[3]);
  const params = new QueryParams(query);
  const proxy = {
    ...base(params.get('remarks') || '', 'vmess', server, port),
    uuid: m[2],
    alterId: Number(params.get('alterId') || 0),
    cipher: m[1] || 'auto',
  };
  if (flag(params, 'tls')) {
    proxy.tls = true;
    applyTls(proxy, { sni: first(params, 'peer', 'sni'), insecure: flag(params, 'allowInsecure') });
  }
  const obfs = params.get('obfs');
  if (obfs === 'websocket' || obfs === 'ws') {
    applyTransport(proxy, { network: 'ws', host: params.get('obfsParam'), path: params.get('path') });
  } else if (obfs === 'grpc') {
    applyTransport(proxy, { network: 'grpc', path: params.get('path') });
  }
  return prune(proxy);
}

function parseVmessStd(link) {
  const u = parseStdUri(link);
  const p = u.params;
  const proxy = {
    ...base(u.name, 'vmess', u.server, u.port),
    uuid: u.userinfo,
    alterId: Number(p.get('alterId') || p.get('aid') || 0),
    cipher: p.get('encryption') || 'auto',
  };
  applyStdSecurity(proxy, p);
  applyStdTransport(proxy, p);
  return prune(proxy);
}

// ---------- VLESS ----------

function applyStdSecurity(proxy, p) {
  const security = (p.get('security') || '').toLowerCase();
  if (security === 'tls' || security === 'xtls' || security === 'reality') {
    proxy.tls = true;
    applyTls(proxy, {
      sni: first(p, 'sni', 'peer'),
      alpn: p.get('alpn'),
      fp: p.get('fp'),
      insecure: flag(p, 'allowInsecure', 'insecure'),
    });
  }
  if (security === 'reality') {
    proxy['reality-opts'] = prune({ 'public-key': p.get('pbk'), 'short-id': p.get('sid') ?? undefined });
    if (!proxy['client-fingerprint']) proxy['client-fingerprint'] = 'chrome';
  }
}

function applyStdTransport(proxy, p) {
  const type = (p.get('type') || 'tcp').toLowerCase();
  let extra;
  if (type === 'xhttp' && p.get('extra')) {
    try {
      const e = JSON.parse(p.get('extra'));
      extra = e.noGRPCHeader ? { 'no-grpc-header': true } : undefined;
    } catch {
      // extra 为可选增强参数，解析失败时忽略
    }
  }
  applyTransport(proxy, {
    network: type,
    host: p.get('host'),
    path: p.get('path'),
    serviceName: p.get('serviceName'),
    headerType: p.get('headerType'),
    mode: p.get('mode'),
    extra,
  });
}

function parseVless(link) {
  const u = parseStdUri(link);
  const p = u.params;
  const proxy = {
    ...base(u.name, 'vless', u.server, u.port),
    uuid: u.userinfo,
    udp: true,
    flow: p.get('flow') || undefined,
    'packet-encoding': p.get('packetEncoding') || undefined,
  };
  const encryption = p.get('encryption');
  if (encryption && encryption !== 'none') proxy.encryption = encryption;
  applyStdSecurity(proxy, p);
  applyStdTransport(proxy, p);
  return prune(proxy);
}

// ---------- Trojan ----------

function parseTrojan(link) {
  const u = parseStdUri(link);
  const p = u.params;
  const proxy = { ...base(u.name, 'trojan', u.server, u.port), password: u.userinfo, udp: true };
  applyTls(proxy, {
    sni: first(p, 'sni', 'peer'),
    alpn: p.get('alpn'),
    fp: p.get('fp'),
    insecure: flag(p, 'allowInsecure', 'insecure'),
    sniKey: 'sni',
  });
  if ((p.get('security') || '').toLowerCase() === 'reality') {
    proxy['reality-opts'] = prune({ 'public-key': p.get('pbk'), 'short-id': p.get('sid') ?? undefined });
  }
  applyStdTransport(proxy, p);
  return prune(proxy);
}

// ---------- Hysteria / Hysteria2 / TUIC / AnyTLS ----------

function parseHysteria2(link) {
  const u = parseStdUri(link);
  const p = u.params;
  const mport = p.get('mport') || (u.portSpec !== String(u.port) ? u.portSpec : undefined);
  const obfs = p.get('obfs');
  return prune({
    ...base(u.name, 'hysteria2', u.server, u.port),
    ports: mport,
    password: u.userinfo,
    obfs: obfs && obfs !== 'none' ? obfs : undefined,
    'obfs-password': obfs && obfs !== 'none' ? p.get('obfs-password') : undefined,
    sni: first(p, 'sni', 'peer'),
    'skip-cert-verify': flag(p, 'insecure', 'allowInsecure') || undefined,
    alpn: splitList(p.get('alpn')),
    fingerprint: p.get('pinSHA256') || undefined,
    up: p.get('upmbps') || undefined,
    down: p.get('downmbps') || undefined,
  });
}

function parseHysteria(link) {
  const u = parseStdUri(link);
  const p = u.params;
  return prune({
    ...base(u.name, 'hysteria', u.server, u.port),
    ports: p.get('mport') || undefined,
    'auth-str': p.get('auth') || u.userinfo || undefined,
    protocol: p.get('protocol') || undefined,
    up: p.get('upmbps') || p.get('up') || '10',
    down: p.get('downmbps') || p.get('down') || '50',
    obfs: p.get('obfs') || p.get('obfsParam') || undefined,
    sni: first(p, 'peer', 'sni'),
    'skip-cert-verify': flag(p, 'insecure') || undefined,
    alpn: splitList(p.get('alpn')),
  });
}

function parseTuic(link) {
  const u = parseStdUri(link);
  const p = u.params;
  const colon = u.userinfo.indexOf(':');
  const proxy = {
    ...base(u.name, 'tuic', u.server, u.port),
    uuid: colon >= 0 ? u.userinfo.slice(0, colon) : u.userinfo,
    password: colon >= 0 ? u.userinfo.slice(colon + 1) : p.get('password') || undefined,
    'congestion-controller': first(p, 'congestion_control', 'congestion-controller'),
    'udp-relay-mode': first(p, 'udp_relay_mode', 'udp-relay-mode'),
    alpn: splitList(p.get('alpn')),
    sni: p.get('sni') || undefined,
    'disable-sni': flag(p, 'disable_sni') || undefined,
    'skip-cert-verify': flag(p, 'allow_insecure', 'allowInsecure', 'insecure') || undefined,
    udp: true,
  };
  if (!proxy.password && p.get('token')) {
    // TUIC v4 使用 token 认证
    delete proxy.uuid;
    proxy.token = p.get('token');
  }
  return prune(proxy);
}

function parseAnyTLS(link) {
  const u = parseStdUri(link);
  const p = u.params;
  const proxy = { ...base(u.name, 'anytls', u.server, u.port), password: u.userinfo, udp: true };
  applyTls(proxy, {
    sni: first(p, 'sni', 'peer'),
    alpn: p.get('alpn'),
    fp: p.get('fp'),
    insecure: flag(p, 'insecure', 'allowInsecure'),
    sniKey: 'sni',
  });
  return prune(proxy);
}

// ---------- SOCKS5 / WireGuard ----------

function parseSocks(link) {
  const u = parseStdUri(link);
  let user = u.userinfo;
  // v2rayN 格式：socks://BASE64(user:pass)@host:port。
  // 普通用户名也可能恰好能按 Base64 解码出乱码，只有解出 "用户:密码" 才采用解码结果。
  if (user && !user.includes(':')) {
    try {
      const decoded = decodeBase64(u.rawUserinfo);
      if (decoded.includes(':')) user = decoded;
    } catch {
      // 不是 Base64，按原文处理
    }
  }
  const colon = user.indexOf(':');
  return prune({
    ...base(u.name, 'socks5', u.server, u.port),
    username: colon >= 0 ? user.slice(0, colon) : user || undefined,
    password: colon >= 0 ? user.slice(colon + 1) : undefined,
    udp: true,
  });
}

function parseWireGuard(link) {
  const u = parseStdUri(link);
  const p = u.params;
  const addresses = splitList(first(p, 'address', 'ip'));
  const ipv4 = addresses.find((a) => !a.includes(':'));
  const ipv6 = addresses.find((a) => a.includes(':'));
  const reserved = p.get('reserved');
  return prune({
    ...base(u.name, 'wireguard', u.server, u.port),
    'private-key': u.userinfo || p.get('privatekey'),
    'public-key': first(p, 'publickey', 'publicKey'),
    'pre-shared-key': first(p, 'presharedkey', 'pre-shared-key'),
    ip: ipv4?.replace(/\/\d+$/, ''),
    ipv6: ipv6?.replace(/\/\d+$/, ''),
    mtu: p.get('mtu') ? Number(p.get('mtu')) : undefined,
    reserved: reserved ? (reserved.includes(',') ? splitList(reserved).map(Number) : reserved) : undefined,
    udp: true,
  });
}
