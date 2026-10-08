import { handleSub } from '../src/handler.js';

export const onRequest = ({ request, env }) => handleSub(request, env);
