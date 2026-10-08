// 把 mihomo 代理对象转换回分享链接，用于输出 v2rayN / Shadowrocket 等通用 Base64 订阅。

import { encodeBase64, formatHost } from '../utils.js';

const enc = encodeURIComponent;

function query(pairs) {
  const s = pairs
    .filter(([, v]) => v !== undefined && v !== null && v !== '' && v !== false)
    .map(([k, v]) => `${k}=${enc(v === true ? '1' : String(v))}`)
    .join('&');
  return s ? `?${s}` : '';
}

const hostPort = (p) => `${formatHost(p.server)}:${p.port}`;
const fragment = (p) => `#${enc(p.name)}`;
const joinList = (v) => (Array.isArray(v) ? v.join(',') : v);

// 传输层参数（VLESS / Trojan / VMess 标准链接共用）
function transportPairs(p) {
  const net = p.network || 'tcp';
  if (net === 'ws') {
    const o = p['ws-opts'] || {};
    return [
      ['type', o['v2ray-http-upgrade'] ? 'httpupgrade' : 'ws'],
      ['path', o.path],
      ['host', o.headers?.Host || o.headers?.host],
    ];
  }
  if (net === 'grpc') return [['type', 'grpc'], ['serviceName', p['grpc-opts']?.['grpc-service-name']]];
  if (net === 'h2') {
    const o = p['h2-opts'] || {};
    return [['type', 'http'], ['path', o.path], ['host', joinList(o.host)]];
  }
  if (net === 'http') {
    const o = p['http-opts'] || {};
    return [
      ['type', 'tcp'],
      ['headerType', 'http'],
      ['path', joinList(o.path)],
      ['host', joinList(o.headers?.Host)],
    ];
  }
  if (net === 'xhttp') {
    const o = p['xhttp-opts'] || {};
    return [['type', 'xhttp'], ['path', o.path], ['host', o.host], ['mode', o.mode]];
  }
  return [['type', 'tcp']];
}

function tlsPairs(p, sniKey = 'servername') {
  const reality = p['reality-opts'];
  if (!p.tls && !reality && p.type !== 'trojan') return [['security', 'none']];
  return [
    ['security', reality ? 'reality' : 'tls'],
    ['sni', p[sniKey] || p.sni || p.servername],
    ['alpn', joinList(p.alpn)],
    ['fp', p['client-fingerprint']],
    ['pbk', reality?.['public-key']],
    ['sid', reality?.['short-id']],
    ['allowInsecure', p['skip-cert-verify'] ? 1 : undefined],
  ];
}

const CONVERTERS = {
  ss(p) {
    const is2022 = /^2022-/.test(p.cipher);
    const userinfo = is2022 ? `${enc(p.cipher)}:${enc(p.password)}` : encodeBase64(`${p.cipher}:${p.password}`, true);
    let plugin;
    const o = p['plugin-opts'] || {};
    if (p.plugin === 'obfs') plugin = ['obfs-local', `obfs=${o.mode || 'http'}`, o.host && `obfs-host=${o.host}`];
    else if (p.plugin === 'v2ray-plugin') {
      plugin = ['v2ray-plugin', `mode=${o.mode || 'websocket'}`, o.host && `host=${o.host}`, o.path && `path=${o.path}`, o.tls && 'tls'];
    } else if (p.plugin) return null;
    return `ss://${userinfo}@${hostPort(p)}${query([['plugin', plugin?.filter(Boolean).join(';')]])}${fragment(p)}`;
  },

  ssr(p) {
    const b64 = (s) => encodeBase64(String(s ?? ''), true);
    // 解析时把 none 改成了 Clash 认识的 dummy，输出链接要改回来
    const cipher = p.cipher === 'dummy' ? 'none' : p.cipher;
    const main = [p.server, p.port, p.protocol, cipher, p.obfs, b64(p.password)].join(':');
    const params = `obfsparam=${b64(p['obfs-param'])}&protoparam=${b64(p['protocol-param'])}&remarks=${b64(p.name)}`;
    return `ssr://${b64(`${main}/?${params}`)}`;
  },

  vmess(p) {
    const net = p.network || 'tcp';
    const t = Object.fromEntries(transportPairs(p));
    const json = {
      v: '2',
      ps: p.name,
      add: p.server,
      port: String(p.port),
      id: p.uuid,
      aid: String(p.alterId ?? 0),
      scy: p.cipher || 'auto',
      net: net === 'h2' ? 'h2' : t.type,
      type: t.headerType || (net === 'xhttp' ? t.mode : 'none'),
      host: t.host || '',
      path: net === 'grpc' ? t.serviceName || '' : t.path || '',
      tls: p.tls ? 'tls' : '',
      sni: p.servername || '',
      alpn: joinList(p.alpn) || '',
      fp: p['client-fingerprint'] || '',
    };
    return `vmess://${encodeBase64(JSON.stringify(json))}`;
  },

  vless(p) {
    return `vless://${enc(p.uuid)}@${hostPort(p)}${query([
      ['encryption', p.encryption || 'none'],
      ['flow', p.flow],
      ...tlsPairs(p),
      ...transportPairs(p),
    ])}${fragment(p)}`;
  },

  trojan(p) {
    return `trojan://${enc(p.password)}@${hostPort(p)}${query([...tlsPairs(p, 'sni'), ...transportPairs(p)])}${fragment(p)}`;
  },

  hysteria2(p) {
    return `hysteria2://${enc(p.password || '')}@${hostPort(p)}${query([
      ['sni', p.sni],
      ['insecure', p['skip-cert-verify'] ? 1 : undefined],
      ['obfs', p.obfs],
      ['obfs-password', p['obfs-password']],
      ['mport', p.ports],
      ['alpn', joinList(p.alpn)],
      ['pinSHA256', p.fingerprint],
    ])}${fragment(p)}`;
  },

  hysteria(p) {
    return `hysteria://${hostPort(p)}${query([
      ['protocol', p.protocol],
      ['auth', p['auth-str']],
      ['peer', p.sni],
      ['insecure', p['skip-cert-verify'] ? 1 : undefined],
      ['upmbps', p.up],
      ['downmbps', p.down],
      ['alpn', joinList(p.alpn)],
      ['obfs', p.obfs],
      ['mport', p.ports],
    ])}${fragment(p)}`;
  },

  tuic(p) {
    if (!p.uuid) return null;
    return `tuic://${enc(p.uuid)}:${enc(p.password || '')}@${hostPort(p)}${query([
      ['congestion_control', p['congestion-controller']],
      ['udp_relay_mode', p['udp-relay-mode']],
      ['alpn', joinList(p.alpn)],
      ['sni', p.sni],
      ['allow_insecure', p['skip-cert-verify'] ? 1 : undefined],
      ['disable_sni', p['disable-sni'] ? 1 : undefined],
    ])}${fragment(p)}`;
  },

  anytls(p) {
    return `anytls://${enc(p.password)}@${hostPort(p)}${query([
      ['sni', p.sni],
      ['insecure', p['skip-cert-verify'] ? 1 : undefined],
      ['fp', p['client-fingerprint']],
      ['alpn', joinList(p.alpn)],
    ])}${fragment(p)}`;
  },

  socks5(p) {
    const auth = p.username ? `${encodeBase64(`${p.username}:${p.password || ''}`, true)}@` : '';
    return `socks://${auth}${hostPort(p)}${fragment(p)}`;
  },

  wireguard(p) {
    const address = [p.ip && `${p.ip}/32`, p.ipv6 && `${p.ipv6}/128`].filter(Boolean).join(',');
    return `wireguard://${enc(p['private-key'])}@${hostPort(p)}${query([
      ['publickey', p['public-key']],
      ['presharedkey', p['pre-shared-key']],
      ['address', address],
      ['mtu', p.mtu],
      ['reserved', joinList(p.reserved)],
    ])}${fragment(p)}`;
  },
};

export function proxyToLink(p) {
  const fn = CONVERTERS[p.type];
  return fn ? fn(p) : null;
}

export function generateLinks(proxies, warnings) {
  const lines = [];
  const skipped = [];
  for (const p of proxies) {
    const link = proxyToLink(p);
    if (link) lines.push(link);
    else skipped.push(p.name);
  }
  if (skipped.length) warnings.push(`${skipped.length} 个节点无法转换为分享链接：${skipped.slice(0, 5).join('、')}`);
  return lines;
}
