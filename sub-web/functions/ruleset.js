import { handleRuleset } from '../src/ruleset.js';

export const onRequest = ({ request, env }) => handleRuleset(request, env);
