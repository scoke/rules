import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLink } from '../src/parsers/links.js';
import { parseSubscription } from '../src/parsers/subscription.js';
import { proxyToLink } from '../src/generators/links.js';
import { decodeBase64, encodeBase64 } from '../src/utils.js';

test('ss: SIP002 Base64 用户信息与插件', () => {
  const p = parseLink('ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#HK%2001');
  assert.deepEqual(p, {
    name: 'HK 01',
    type: 'ss',
    server: '1.2.3.4',
    port: 8388,
    cipher: 'aes-256-gcm',
    password: 'pass',
    plugin: 'obfs',
    'plugin-opts': { mode: 'http', host: 'example.com' },
  });
});

test('ss: 2022 明文用户信息保留 +，旧式整体 Base64', () => {
  const p = parseLink('ss://2022-blake3-aes-128-gcm:abc+def%3D@[2001:db8::1]:443#v6');
  assert.equal(p.cipher, '2022-blake3-aes-128-gcm');
  assert.equal(p.password, 'abc+def=');
  assert.equal(p.server, '2001:db8::1');

  const legacy = parseLink(`ss://${encodeBase64('chacha20-ietf-poly1305:p:w@example.com:8080')}#legacy`);
  assert.equal(legacy.password, 'p:w');
  assert.equal(legacy.server, 'example.com');
  assert.equal(legacy.port, 8080);
});

test('vmess: v2rayN JSON 格式', () => {
  const json = { v: '2', ps: '美国 01', add: 'a.com', port: '443', id: 'uuid-1', aid: '0', net: 'grpc', path: 'svc', tls: 'tls', sni: 's.com', fp: 'chrome' };
  const p = parseLink(`vmess://${encodeBase64(JSON.stringify(json))}`);
  assert.equal(p.name, '美国 01');
  assert.equal(p.port, 443);
  assert.equal(p.tls, true);
  assert.equal(p.servername, 's.com');
  assert.equal(p['client-fingerprint'], 'chrome');
  assert.equal(p.network, 'grpc');
  assert.deepEqual(p['grpc-opts'], { 'grpc-service-name': 'svc' });
});

test('vless: reality + vision', () => {
  const p = parseLink('vless://uuid-2@jp.com:443?security=reality&sni=www.apple.com&pbk=PUBKEY+x&sid=ab&fp=safari&flow=xtls-rprx-vision&type=tcp#JP');
  assert.equal(p.flow, 'xtls-rprx-vision');
  assert.equal(p.tls, true);
  assert.equal(p.servername, 'www.apple.com');
  assert.deepEqual(p['reality-opts'], { 'public-key': 'PUBKEY+x', 'short-id': 'ab' });
  assert.equal(p['client-fingerprint'], 'safari');
  assert.equal(p.network, undefined);
});

test('trojan / hysteria2 / tuic / anytls', () => {
  const t = parseLink('trojan://pw@t.com:443?sni=s.com&type=ws&path=%2Fws&host=h.com&allowInsecure=1#T');
  assert.equal(t.sni, 's.com');
  assert.equal(t['skip-cert-verify'], true);
  assert.deepEqual(t['ws-opts'], { path: '/ws', headers: { Host: 'h.com' } });

  const h = parseLink('hy2://pw@h.com:443,20000-30000/?sni=s.com&obfs=salamander&obfs-password=op#H');
  assert.equal(h.type, 'hysteria2');
  assert.equal(h.port, 443);
  assert.equal(h.ports, '443,20000-30000');
  assert.equal(h['obfs-password'], 'op');

  const u = parseLink('tuic://uuid:pass@u.com:443?congestion_control=bbr&alpn=h3&udp_relay_mode=native#U');
  assert.equal(u.uuid, 'uuid');
  assert.equal(u.password, 'pass');
  assert.deepEqual(u.alpn, ['h3']);

  const a = parseLink('anytls://p%40ss@a.com:45531?sni=a.com&insecure=1#scoke');
  assert.equal(a.type, 'anytls');
  assert.equal(a.password, 'p@ss');
  assert.equal(a['skip-cert-verify'], true);
});

test('ssr', () => {
  const b64 = (s) => encodeBase64(s, true);
  const link = `ssr://${b64(`1.1.1.1:443:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:${b64('pw')}/?obfsparam=${b64('o.com')}&remarks=${b64('SSR 节点')}`)}`;
  const p = parseLink(link);
  assert.equal(p.name, 'SSR 节点');
  assert.equal(p.protocol, 'auth_aes128_md5');
  assert.equal(p.obfs, 'tls1.2_ticket_auth');
  assert.equal(p['obfs-param'], 'o.com');
  assert.equal(p.password, 'pw');
});

test('分享链接往返转换保持字段一致', () => {
  const links = [
    'ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#A',
    'vless://uuid-2@jp.com:443?security=reality&sni=www.apple.com&pbk=KEY&sid=ab&fp=chrome&flow=xtls-rprx-vision&type=tcp#B',
    'vless://uuid-3@x.com:443?security=tls&sni=x.com&type=ws&path=%2Fp&host=x.com#C',
    'trojan://pw@t.com:443?sni=s.com&type=grpc&serviceName=g#D',
    'hysteria2://pw@h.com:443?sni=s.com#E',
    'tuic://uuid:pass@u.com:443?congestion_control=bbr&alpn=h3#F',
    'anytls://pw@a.com:443?sni=a.com#G',
    `vmess://${encodeBase64(JSON.stringify({ v: '2', ps: 'H', add: 'v.com', port: '443', id: 'id', aid: '0', net: 'ws', host: 'v.com', path: '/v', tls: 'tls' }))}`,
  ];
  for (const link of links) {
    const p = parseLink(link);
    assert.deepEqual(parseLink(proxyToLink(p)), p, link);
  }
});

test('订阅内容：Base64、明文、Clash YAML、错误行', () => {
  const warnings = [];
  const lines = ['trojan://pw@t.com:443#T1', 'vmess://not-base64!!', 'STATUS=剩余流量'];
  const fromB64 = parseSubscription(encodeBase64(lines.join('\n')), warnings);
  assert.equal(fromB64.length, 1);
  assert.equal(warnings.length, 2);

  const yaml = 'proxies:\n  - {name: Y1, type: ss, server: y.com, port: "8388", cipher: aes-128-gcm, password: x}\n  - {name: bad}\nrules: []\n';
  const w2 = [];
  const fromYaml = parseSubscription(yaml, w2);
  assert.equal(fromYaml.length, 1);
  assert.equal(fromYaml[0].port, 8388);
  assert.equal(w2.length, 1);
});

test('socks：明文用户名不会被误当成 Base64；ssr 的 none 加密往返保持不变', () => {
  assert.equal(parseLink('socks://user@1.2.3.4:1080#a').username, 'user');
  assert.deepEqual(
    (({ username, password }) => ({ username, password }))(parseLink(`socks://${encodeBase64('u:p', true)}@1.2.3.4:1080#b`)),
    { username: 'u', password: 'p' },
  );
  const b64 = (s) => encodeBase64(s, true);
  const ssr = `ssr://${b64(`1.1.1.1:443:origin:none:plain:${b64('pw')}/?remarks=${b64('N')}`)}`;
  const p = parseLink(ssr);
  assert.equal(p.cipher, 'dummy');
  assert.equal(parseLink(proxyToLink(p)).cipher, 'dummy');
  assert.match(decodeBase64(proxyToLink(p).slice('ssr://'.length)), /:origin:none:plain:/);
});
