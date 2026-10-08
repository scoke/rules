// /sub 接口：参数与 subconverter 保持兼容，便于沿用已有的订阅链接写法。

import { convert, createFetcher, parseOptions, UserError } from './convert.js';

export const VERSION = 'sub-web 1.0.0';

function textResponse(status, body) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

// 仅用 ASCII 传递警告，前端预览时展示
function encodeWarnings(warnings) {
  let list = warnings.map((w) => w.slice(0, 200));
  let encoded = encodeURIComponent(JSON.stringify(list));
  while (encoded.length > 6000 && list.length > 1) {
    list = list.slice(0, Math.ceil(list.length / 2));
    encoded = encodeURIComponent(JSON.stringify(list));
  }
  return encoded.length > 6000 ? '' : encoded;
}

export async function handleSub(request, env = {}, fetchImpl = fetch) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return textResponse(405, 'Method Not Allowed');
  const q = new URL(request.url).searchParams;
  if (env.ACCESS_TOKEN && q.get('token') !== env.ACCESS_TOKEN) return textResponse(403, '访问令牌错误或缺失（token 参数）');

  let result;
  let opts;
  try {
    opts = parseOptions(request.url);
    result = await convert(opts, createFetcher(fetchImpl));
  } catch (e) {
    if (e instanceof UserError) return textResponse(400, e.message);
    console.error(e);
    return textResponse(500, `转换失败：${e.message}`);
  }

  const headers = new Headers({
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Node-Count': String(result.nodeCount),
  });
  if (result.warnings.length) headers.set('X-Convert-Warnings', encodeWarnings(result.warnings));
  if (result.userinfo) headers.set('subscription-userinfo', result.userinfo);
  if (opts.filename) headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(opts.filename)}`);
  return new Response(request.method === 'HEAD' ? null : result.body, { headers });
}
