const STORAGE_KEY = 'sub-web:options';
const CHECKS = ['emoji', 'udp', 'scv', 'tfo', 'sort', 'append_type', 'expand'];
const TEXTS = ['include', 'exclude', 'filename', 'rename', 'ua', 'token'];
const PREVIEW_LIMIT = 300 * 1024;

const $ = (id) => document.getElementById(id);

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (el.hidden = true), 2200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const el = $('result-url');
    el.select();
    return document.execCommand('copy');
  }
}

function readForm() {
  const form = {
    sources: $('sources').value,
    target: $('target').value,
    config: $('config-custom').value.trim(),
  };
  for (const id of CHECKS) form[id] = $(id).checked;
  for (const id of TEXTS) form[id] = $(id).value.trim();
  return form;
}

function saveOptions(form) {
  const { sources, config, ...options } = form;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(options));
}

function restoreOptions() {
  let saved;
  try {
    saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
  } catch {
    saved = null;
  }
  if (!saved) return;
  $('target').value = saved.target || 'clash';
  for (const id of CHECKS) if (id in saved) $(id).checked = !!saved[id];
  for (const id of TEXTS) if (saved[id]) $(id).value = saved[id];
}

function buildUrl(form) {
  const sources = form.sources
    .split(/[\r\n|]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!sources.length) throw new Error('请填写订阅链接');
  if (form.config && !/^https?:\/\//i.test(form.config)) throw new Error('远程配置需为 http(s) 地址');

  const params = new URLSearchParams();
  params.set('target', form.target === 'clash-list' ? 'clash' : form.target);
  params.set('url', sources.join('|'));
  if (form.config) params.set('config', form.config);
  if (form.include) params.set('include', form.include);
  if (form.exclude) params.set('exclude', form.exclude);
  if (form.rename) params.set('rename', form.rename);
  if (form.filename) params.set('filename', form.filename);
  params.set('emoji', String(form.emoji));
  // 不勾选时不传，保留订阅里各节点的原始设置
  for (const id of ['udp', 'scv', 'tfo', 'sort', 'append_type']) if (form[id]) params.set(id, 'true');
  params.set('expand', String(form.expand));
  if (form.target === 'clash-list') params.set('list', 'true');
  if (form.ua) params.set('ua', form.ua);
  if (form.token) params.set('token', form.token);
  return `${location.origin}/sub?${params}`;
}

function parseLink(input) {
  const u = new URL(input.trim());
  const q = u.searchParams;
  if (!q.get('url')) throw new Error('链接中没有 url 参数');
  $('sources').value = q.get('url').split('|').join('\n');
  const target = (q.get('target') || 'clash').toLowerCase();
  const isClash = ['clash', 'clashmeta', 'clash.meta', 'meta', 'mihomo'].includes(target);
  $('target').value = isClash ? (q.get('list') === 'true' ? 'clash-list' : 'clash') : 'mixed';
  $('config-custom').value = q.get('config') || '';
  for (const id of TEXTS) $(id).value = q.get(id) || '';
  const bool = (k, fallback) => (q.has(k) ? ['true', '1'].includes(q.get(k).toLowerCase()) : fallback);
  $('emoji').checked = bool('emoji', true);
  $('expand').checked = bool('expand', true);
  for (const id of ['udp', 'scv', 'tfo', 'sort', 'append_type']) $(id).checked = bool(id, false);
}

function showResult(url) {
  $('result').hidden = false;
  $('result-url').value = url;
  $('btn-open').href = url;
  $('preview').hidden = true;
}

function decodeBase64Utf8(text) {
  const bin = atob(text.replace(/\s+/g, ''));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

async function preview() {
  const url = $('result-url').value;
  const btn = $('btn-preview');
  btn.disabled = true;
  btn.textContent = '转换中…';
  const meta = $('preview-meta');
  const list = $('preview-warnings');
  const body = $('preview-body');
  list.replaceChildren();
  try {
    const started = performance.now();
    const res = await fetch(url, { cache: 'no-store' });
    let text = await res.text();
    const elapsed = Math.round(performance.now() - started);
    if (!res.ok) {
      meta.textContent = `转换失败（HTTP ${res.status}）`;
      body.textContent = text;
    } else {
      const info = [`节点 ${res.headers.get('X-Node-Count') || '?'} 个`, `${(text.length / 1024).toFixed(1)} KB`, `${elapsed} ms`];
      const userinfo = res.headers.get('subscription-userinfo');
      if (userinfo) info.push(formatUserinfo(userinfo));
      meta.textContent = info.join(' · ');
      const encoded = res.headers.get('X-Convert-Warnings');
      if (encoded) {
        for (const w of JSON.parse(decodeURIComponent(encoded))) {
          const li = document.createElement('li');
          li.textContent = w;
          list.append(li);
        }
      }
      if ($('target').value === 'mixed') {
        try {
          text = decodeBase64Utf8(text);
        } catch {
          // 保持原文
        }
      }
      body.textContent = text.length > PREVIEW_LIMIT ? `${text.slice(0, PREVIEW_LIMIT)}\n\n…（内容过长，仅显示前 300 KB）` : text;
    }
    $('preview').hidden = false;
  } catch (e) {
    toast(`预览失败：${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = '预览配置';
  }
}

function formatUserinfo(value) {
  const fields = Object.fromEntries(
    value.split(';').map((kv) => kv.trim().split('=')).filter(([k, v]) => k && v).map(([k, v]) => [k, Number(v)]),
  );
  const gb = (n) => `${(n / 1024 ** 3).toFixed(2)} GB`;
  const parts = [];
  if (fields.total) parts.push(`流量 ${gb((fields.upload || 0) + (fields.download || 0))} / ${gb(fields.total)}`);
  if (fields.expire) parts.push(`到期 ${new Date(fields.expire * 1000).toLocaleDateString()}`);
  return parts.join(' · ');
}

async function checkBackend() {
  const badge = $('backend-status');
  try {
    const res = await fetch('/version', { cache: 'no-store' });
    if (!res.ok) throw new Error(res.status);
    badge.textContent = (await res.text()).trim();
    badge.className = 'badge ok';
    $('token-field').hidden = res.headers.get('X-Token-Required') !== '1' && !$('token').value;
  } catch {
    badge.textContent = '后端不可用';
    badge.className = 'badge error';
  }
}

function bind() {
  $('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = readForm();
    let url;
    try {
      url = buildUrl(form);
    } catch (err) {
      toast(err.message);
      return;
    }
    saveOptions(form);
    showResult(url);
    toast((await copyText(url)) ? '已生成并复制到剪贴板' : '已生成');
  });

  $('btn-reset').addEventListener('click', () => {
    localStorage.removeItem(STORAGE_KEY);
    $('form').reset();
    $('result').hidden = true;
  });

  $('btn-copy').addEventListener('click', async () => {
    toast((await copyText($('result-url').value)) ? '已复制' : '复制失败，请手动复制');
  });

  $('btn-import').addEventListener('click', () => {
    const url = $('result-url').value;
    const name = $('filename').value.trim();
    location.href = `clash://install-config?url=${encodeURIComponent(url)}${name ? `&name=${encodeURIComponent(name)}` : ''}`;
  });

  $('btn-preview').addEventListener('click', preview);

  $('btn-parse').addEventListener('click', () => {
    try {
      parseLink($('parse-input').value);
      toast('已还原到表单');
      $('form').scrollIntoView({ behavior: 'smooth' });
    } catch (e) {
      toast(`解析失败：${e.message}`);
    }
  });
}

restoreOptions();
bind();
checkBackend();
