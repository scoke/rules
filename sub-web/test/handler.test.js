import test from 'node:test';
import assert from 'node:assert/strict';
import YAML from 'yaml';
import { handleSub } from '../src/handler.js';
import { handleRuleset } from '../src/ruleset.js';
import { decodeBase64, encodeBase64 } from '../src/utils.js';

const NODES = [
  'ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#香港 01',
  'trojan://pw@t.com:443?sni=t.com#日本 01',
  'anytls://pw@us.com:443?sni=us.com#scoke',
  'hysteria2://pw@sg.com:443#剩余流量 10G',
];

const INI = `[custom]
ruleset=🎯 全球直连,https://rules.example/direct.list
ruleset=🚀 节点选择,https://rules.example/proxy.yaml
ruleset=🚀 节点选择,https://rules.example/missing.list
ruleset=不存在的组,https://rules.example/direct.list
ruleset=🎯 全球直连,[]GEOIP,CN
ruleset=🐟 漏网之鱼,[]FINAL
custom_proxy_group=🚀 节点选择\`select\`[]♻️ 自动选择\`[]DIRECT\`.*
custom_proxy_group=♻️ 自动选择\`url-test\`.*\`http://www.gstatic.com/generate_204\`300,,50
custom_proxy_group=🎯 全球直连\`select\`[]DIRECT\`[]🚀 节点选择
custom_proxy_group=🐟 漏网之鱼\`select\`[]🚀 节点选择\`[]DIRECT
exclude_remarks=(剩余|到期)
`;

function mockFetch(calls = []) {
  return async (url, init) => {
    calls.push({ url, ua: init?.headers?.['User-Agent'] });
    const routes = {
      'https://sub.example/a': () =>
        new Response(encodeBase64(NODES.join('\n')), { headers: { 'subscription-userinfo': 'upload=1; download=2; total=3' } }),
      'https://sub.example/yaml': () =>
        new Response('proxies:\n  - {name: Y, type: vless, server: y.com, port: 443, uuid: u, tls: true}\n'),
      'https://cfg.example/c.ini': () => new Response(INI),
      'https://rules.example/direct.list': () => new Response('# 注释\nDOMAIN-SUFFIX,cn\nIP-CIDR,10.0.0.0/8,no-resolve\nUSER-AGENT,x*\n'),
      'https://rules.example/proxy.yaml': () => new Response("payload:\n  - DOMAIN-SUFFIX,google.com\n  - '+.youtube.com'\n"),
    };
    const route = routes[url];
    return route ? route() : new Response('not found', { status: 404 });
  };
}

async function call(params, { env = {}, calls } = {}) {
  const u = new URL('https://sub-web.pages.dev/sub');
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  const res = await handleSub(new Request(u), env, mockFetch(calls));
  return { res, text: await res.text() };
}

test('生成完整 Clash 配置：分组、规则、过滤、警告', async () => {
  const calls = [];
  const { res, text } = await call({ target: 'clash', url: 'https://sub.example/a', config: 'https://cfg.example/c.ini' }, { calls });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('subscription-userinfo'), 'upload=1; download=2; total=3');
  assert.equal(res.headers.get('X-Node-Count'), '3');
  assert.equal(calls.find((c) => c.url === 'https://sub.example/a').ua, 'clash.meta');

  const doc = YAML.parse(text);
  assert.deepEqual(
    doc.proxies.map((p) => p.name),
    ['🇭🇰 香港 01', '🇯🇵 日本 01', 'scoke'],
  );
  const groups = Object.fromEntries(doc['proxy-groups'].map((g) => [g.name, g]));
  assert.equal(groups['♻️ 自动选择'].type, 'url-test');
  assert.equal(groups['♻️ 自动选择'].tolerance, 50);
  assert.deepEqual(doc.rules, [
    'DOMAIN-SUFFIX,cn,🎯 全球直连',
    'IP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve',
    'DOMAIN-SUFFIX,google.com,🚀 节点选择',
    'DOMAIN-SUFFIX,youtube.com,🚀 节点选择',
    'GEOIP,CN,🎯 全球直连',
    'MATCH,🐟 漏网之鱼',
  ]);
  const warnings = JSON.parse(decodeURIComponent(res.headers.get('X-Convert-Warnings')));
  assert.ok(warnings.some((w) => w.includes('missing.list')));
  assert.ok(warnings.some((w) => w.includes('不存在的组')));
  assert.ok(warnings.some((w) => w.includes('USER-AGENT×1')));
  assert.match(text, /^# 由 sub-web 生成于/);
});

test('expand=false 生成 rule-providers，不下载规则集', async () => {
  const calls = [];
  const { text } = await call(
    { target: 'clash', url: 'https://sub.example/a', config: 'https://cfg.example/c.ini', expand: 'false' },
    { calls },
  );
  assert.ok(!calls.some((c) => c.url.startsWith('https://rules.example')));
  const doc = YAML.parse(text);
  assert.deepEqual(doc['rule-providers'].proxy, {
    type: 'http',
    behavior: 'classical',
    format: 'text',
    url: 'https://sub-web.pages.dev/ruleset?url=https%3A%2F%2Frules.example%2Fproxy.yaml',
    interval: 86400,
  });
  assert.equal(doc.rules[0], 'RULE-SET,direct,🎯 全球直连');
});

test('/ruleset 把规则集规范为 classical 文本，并沿用访问令牌', async () => {
  const env = { ACCESS_TOKEN: 'secret' };
  const { text } = await call(
    { url: 'https://sub.example/a', config: 'https://cfg.example/c.ini', expand: 'false', token: 'secret' },
    { env },
  );
  const provider = YAML.parse(text)['rule-providers'].proxy;
  assert.match(provider.url, /&token=secret$/);

  const relay = (url) => handleRuleset(new Request(url), env, mockFetch());
  assert.equal((await relay('https://sub-web.pages.dev/ruleset?url=https%3A%2F%2Frules.example%2Fproxy.yaml')).status, 403);
  const res = await relay(provider.url);
  assert.equal(res.status, 200);
  const lines = (await res.text()).split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepEqual(lines, ['DOMAIN-SUFFIX,google.com', 'DOMAIN-SUFFIX,youtube.com']);

  const direct = await handleRuleset(
    new Request('https://x/ruleset?url=https%3A%2F%2Frules.example%2Fdirect.list'),
    {},
    mockFetch(),
  );
  const body = await direct.text();
  assert.match(body, /USER-AGENT×1/);
  assert.match(body, /^IP-CIDR,10\.0\.0\.0\/8,no-resolve$/m);
  const missing = await handleRuleset(new Request('https://x/ruleset?url=https%3A%2F%2Frules.example%2Fnope'), {}, mockFetch());
  assert.equal(missing.status, 502);
});

test('多个来源、直接粘贴节点、include / emoji / udp 参数', async () => {
  const { text } = await call({
    target: 'clash',
    list: 'true',
    url: `https://sub.example/yaml|${NODES[0]}`,
    include: '香港|Y',
    emoji: 'false',
    udp: 'true',
  });
  const doc = YAML.parse(text);
  assert.deepEqual(Object.keys(doc), ['proxies']);
  assert.deepEqual(
    doc.proxies.map((p) => [p.name, p.udp]),
    [
      ['Y', true],
      ['香港 01', true],
    ],
  );
});

test('mixed 输出 Base64 分享链接', async () => {
  const { res, text } = await call({ target: 'mixed', url: 'https://sub.example/a', filename: '我的订阅' });
  const lines = decodeBase64(text).split('\n');
  assert.equal(lines.length, 4);
  assert.ok(lines[0].startsWith('ss://'));
  assert.equal(res.headers.get('Content-Disposition'), "attachment; filename*=UTF-8''%E6%88%91%E7%9A%84%E8%AE%A2%E9%98%85");
});

test('错误处理与访问令牌', async () => {
  assert.equal((await call({ target: 'clash' })).res.status, 400);
  assert.equal((await call({ target: 'surge', url: 'https://sub.example/a' })).res.status, 400);
  const failed = await call({ url: 'https://sub.example/404' });
  assert.equal(failed.res.status, 400);
  assert.match(failed.text, /没有解析到任何节点[\s\S]*HTTP 404/);
  const badConfig = await call({ url: 'https://sub.example/a', config: 'file:///etc/passwd' });
  assert.equal(badConfig.res.status, 400);

  const env = { ACCESS_TOKEN: 'secret' };
  assert.equal((await call({ url: 'https://sub.example/a' }, { env })).res.status, 403);
  assert.equal((await call({ url: 'https://sub.example/a', token: 'secret' }, { env })).res.status, 200);
});
