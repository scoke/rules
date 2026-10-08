// /sub 与 /ruleset 共用的响应与访问令牌校验，保证两个接口的行为一致。

export function textResponse(status, body, extra = {}) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
  });
}

// 设置了 ACCESS_TOKEN 时要求 token 参数一致；不通过时返回 403 响应，通过时返回 null。
export function checkToken(params, env) {
  if (env?.ACCESS_TOKEN && params.get('token') !== env.ACCESS_TOKEN) {
    return textResponse(403, '访问令牌错误或缺失（token 参数）');
  }
  return null;
}
