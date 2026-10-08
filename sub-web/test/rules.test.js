import test from 'node:test';
import assert from 'node:assert/strict';
import { attachGroup, normalizeRule, parseRuleList, RuleCollector } from '../src/rules.js';
import { parseExternalConfig, parseGroupLine, parseRulesetLine } from '../src/config.js';
import { buildGroups } from '../src/groups.js';
import { generateClash } from '../src/generators/clash.js';
import YAML from 'yaml';

const G = '🚀 节点选择';

test('规则规范化与附加策略组', () => {
  const cases = [
    ['DOMAIN-SUFFIX,google.com', 'DOMAIN-SUFFIX,google.com,G'],
    ['IP-CIDR,1.0.0.0/8,no-resolve', 'IP-CIDR,1.0.0.0/8,G,no-resolve'],
    ['IP-CIDR,1.0.0.0/8,Proxy,no-resolve', 'IP-CIDR,1.0.0.0/8,G,no-resolve'],
    ['GEOIP,CN', 'GEOIP,CN,G'],
    ['FINAL', 'MATCH,G'],
    ['HOST-SUFFIX,a.com', 'DOMAIN-SUFFIX,a.com,G'],
    ["  - '+.example.com'", 'DOMAIN-SUFFIX,example.com,G'],
    ['- 10.0.0.0/8', 'IP-CIDR,10.0.0.0/8,G'],
    ['AND,((DOMAIN,a.com),(NETWORK,UDP))', 'AND,((DOMAIN,a.com),(NETWORK,UDP)),G'],
  ];
  for (const [input, expected] of cases) assert.equal(attachGroup(normalizeRule(input), 'G'), expected, input);
  assert.equal(normalizeRule('# 注释'), null);
  assert.equal(normalizeRule('payload:'), null);
  assert.deepEqual(normalizeRule('USER-AGENT,Foo*'), { unsupported: 'USER-AGENT' });
  assert.equal(attachGroup(normalizeRule('- example.com', 'clash-domain'), 'G'), 'DOMAIN,example.com,G');
});

test('规则列表统计不支持的类型，并去掉重复匹配条件', () => {
  const { rules, unsupported } = parseRuleList('DOMAIN,a.com\nURL-REGEX,^http://x\nDOMAIN,a.com\n');
  assert.equal(rules.length, 2);
  assert.equal(unsupported.get('URL-REGEX'), 1);
  const c = new RuleCollector();
  for (const r of rules) c.add(r, 'A');
  c.add(normalizeRule('DOMAIN,a.com'), 'B');
  assert.deepEqual(c.rules, ['DOMAIN,a.com,A']);
});

test('解析 ruleset 与 custom_proxy_group 行', () => {
  assert.deepEqual(parseRulesetLine('🎯 全球直连,[]GEOIP,CN'), { group: '🎯 全球直连', inline: 'GEOIP,CN' });
  assert.deepEqual(parseRulesetLine('X,clash-domain:https://a.com/r.yaml,3600'), {
    group: 'X',
    url: 'https://a.com/r.yaml',
    format: 'clash-domain',
    interval: 3600,
  });
  assert.deepEqual(parseGroupLine('♻️ 自动选择`url-test`.*`http://www.gstatic.com/generate_204`300,,50'), {
    name: '♻️ 自动选择',
    type: 'url-test',
    items: ['.*'],
    url: 'http://www.gstatic.com/generate_204',
    interval: 300,
    tolerance: 50,
  });

  const cfg = parseExternalConfig(
    '[custom]\n;注释\nruleset=A,https://x/a.list\ncustom_proxy_group=A`select`.*\nenable_rule_generator=true\nexclude_remarks=(到期|剩余)\nrename=\\s*测试@\n',
    [],
  );
  assert.equal(cfg.rulesets.length, 1);
  assert.equal(cfg.groups.length, 1);
  assert.deepEqual(cfg.excludeRemarks, ['(到期|剩余)']);
  assert.deepEqual(cfg.renames, [{ pattern: '\\s*测试', replacement: '' }]);
});

test('策略组：自引用、循环引用、空组与正则', () => {
  const defs = [
    parseGroupLine(`${G}\`select\`[]🚀 手动切换\`[]🇺🇲 美国节点\`[]DIRECT`),
    parseGroupLine(`🚀 手动切换\`select\`[]🇺🇲 美国节点\`[]${G}\`[]🚀 手动切换\`[]不存在\`[]direct`),
    parseGroupLine('🇺🇲 美国节点`select`scoke`(美|US)'),
    parseGroupLine('🇰🇷 韩国节点`select`(韩|KR)'),
  ];
  const warnings = [];
  const groups = buildGroups(defs, ['🇺🇸 美国 01', 'scoke', '🇭🇰 香港'], warnings);
  const byName = Object.fromEntries(groups.map((g) => [g.name, g.proxies]));
  assert.deepEqual(byName[G], ['🚀 手动切换', '🇺🇲 美国节点', 'DIRECT']);
  assert.deepEqual(byName['🚀 手动切换'], ['🇺🇲 美国节点', 'DIRECT']);
  assert.deepEqual(byName['🇺🇲 美国节点'], ['scoke', '🇺🇸 美国 01']);
  assert.deepEqual(byName['🇰🇷 韩国节点'], ['DIRECT']);
  assert.ok(warnings.some((w) => w.includes('循环')));
  assert.ok(warnings.some((w) => w.includes('不存在')));
});

test('规则逐行输出：需要转义的字符串经 YAML 解析后保持原样', () => {
  const rules = [
    'DOMAIN-SUFFIX,google.com,🚀 节点选择',
    'IP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve',
    'DOMAIN-KEYWORD,a: b,G',
    'DOMAIN,x.com,G #1',
    'AND,((DOMAIN,a.com),(NETWORK,UDP)),G',
    "'quoted",
    'MATCH,G:',
    'DOMAIN,a b,G',
  ];
  const text = generateClash({ proxies: [], groups: [], rules, header: [] });
  assert.deepEqual(YAML.parse(text).rules, rules);
  assert.match(text, /^ {2}- DOMAIN-SUFFIX,google\.com,🚀 节点选择$/m);
});
