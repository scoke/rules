import { VERSION } from '../src/handler.js';

export const onRequest = ({ env }) =>
  new Response(`${VERSION} backend\n`, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      // 告知前端是否需要填写访问令牌
      'X-Token-Required': env.ACCESS_TOKEN ? '1' : '0',
    },
  });
