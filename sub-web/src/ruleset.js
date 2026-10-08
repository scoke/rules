// /ruleset 接口：expand=false 时 rule-providers 指向这里。
// 下载原始规则集并规范为 mihomo classical 文本，客户端只需能访问本站，无需直连 GitHub；
// 输出只包含规则行，不会原样转发任意内容。

import { createFetcher } from './convert.js';
import { parseRuleList } from './rules.js';
import { checkToken, textResponse } from './http.js';
import { QueryParams } from './utils.js';

const FORMATS = new Set(['clash-domain', 'clash-ipcidr', 'clash-classic']);

export async function handleRuleset(request, env = {}, fetchImpl = fetch) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return textResponse(405, 'Method Not Allowed');
  const q = new QueryParams(new URL(request.url).search.slice(1));
  const denied = checkToken(q, env);
  if (denied) return denied;
  const url = q.get('url');
  if (!url) return textResponse(400, '缺少 url 参数');
  const format = FORMATS.has(q.get('type')) ? q.get('type') : undefined;

  let text;
  try {
    ({ text } = await createFetcher(fetchImpl)(url, { cacheTtl: 3600 }));
  } catch (e) {
    return textResponse(502, `规则集下载失败：${e.message}`);
  }
  const { rules, unsupported } = parseRuleList(text, format);
  const lines = [`# 由 sub-web 转换自 ${url}，共 ${rules.length} 条`];
  if (unsupported.size) {
    lines.push(`# 已跳过 Clash 不支持的规则：${[...unsupported].map(([t, n]) => `${t}×${n}`).join('，')}`);
  }
  for (const r of rules) lines.push(r.body);
  return textResponse(200, request.method === 'HEAD' ? null : `${lines.join('\n')}\n`, {
    'Cache-Control': 'public, max-age=3600',
  });
}
