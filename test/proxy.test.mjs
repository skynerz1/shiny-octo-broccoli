import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import worker from '../src/index.js';
import { startMockOrigin } from './mock-origin.mjs';

const SECRET = 'test-secret-0123456789abcdef0123456789abcdef';

// Workers provide the Cache API globally; Node does not.
globalThis.caches = { default: makeCache() };

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + signature;
}

function makeCache() {
  const store = new Map();
  return {
    async match(request) {
      const stored = store.get(request.url);
      if (!stored) return undefined;
      return new Response(stored.body, { status: stored.status, headers: stored.headers });
    },
    async put(request, response) {
      const body = await response.arrayBuffer();
      store.set(request.url, {
        body,
        status: response.status,
        headers: [...response.headers.entries()],
      });
    },
  };
}

function makeContext() {
  const pending = [];
  return {
    waitUntil(promise) {
      pending.push(promise);
    },
    async flush() {
      await Promise.all(pending);
      pending.length = 0;
    },
  };
}

function makeEnv(overrides = {}) {
  return {
    PROXY_SECRET: SECRET,
    ALLOW_PRIVATE_HOSTS: '1',
    ...overrides,
  };
}

async function call(path, env, ctx, init) {
  const response = await worker.fetch(new Request('http://proxy.test' + path, init), env, ctx);
  return response;
}

test('health endpoint', async () => {
  const ctx = makeContext();
  const response = await call('/health', makeEnv(), ctx);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true, service: 'divhard-media-proxy' });
});

test('rejects a bad signature and expired tokens', async () => {
  const ctx = makeContext();
  const env = makeEnv();
  const now = Math.floor(Date.now() / 1000);

  const valid = sign({ u: 'https://example.com/x.m3u8', r: '', k: 'hls', e: now + 60 });
  const tampered = valid.slice(0, -1) + (valid.endsWith('A') ? 'B' : 'A');
  assert.equal((await call('/p/' + tampered, env, ctx)).status, 403);

  const expired = sign({ u: 'https://example.com/x.m3u8', r: '', k: 'hls', e: now - 10 });
  assert.equal((await call('/p/' + expired, env, ctx)).status, 403);
});

test('blocks private hosts unless explicitly allowed', async () => {
  const origin = await startMockOrigin();
  try {
    const token = sign({
      u: origin.baseUrl + '/master.m3u8',
      r: 'https://embed.example/',
      k: 'hls',
      e: Math.floor(Date.now() / 1000) + 60,
    });
    const ctx = makeContext();
    const response = await call('/p/' + token, makeEnv({ ALLOW_PRIVATE_HOSTS: '0' }), ctx);
    assert.equal(response.status, 403);
    assert.match(await response.text(), /Blocked upstream host/);
  } finally {
    await origin.close();
  }
});

test('rewrites master and variant playlists, forwards referer, proxies keys and segments', async () => {
  const origin = await startMockOrigin();
  try {
    const ctx = makeContext();
    const env = makeEnv();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const masterToken = sign({
      u: origin.baseUrl + '/master.m3u8',
      r: 'https://embed.example/watch',
      k: 'hls',
      e: exp,
    });

    const master = await call('/p/' + masterToken, env, ctx);
    assert.equal(master.status, 200);
    const masterBody = await master.text();
    assert.match(masterBody, /^#EXTM3U/m);
    assert.match(masterBody, /#MASTER-REFERER:https:\/\/embed\.example\/watch/);
    assert.match(masterBody, /http:\/\/proxy\.test\/p\//);
    assert.doesNotMatch(masterBody, /^v1\/index\.m3u8$/m);

    const variantUrl = masterBody
      .split('\n')
      .find((line) => line.startsWith('http://proxy.test/p/'));
    assert.ok(variantUrl, 'variant URL was rewritten');

    const variant = await call(new URL(variantUrl).pathname, env, ctx);
    assert.equal(variant.status, 200);
    const variantBody = await variant.text();
    assert.match(variantBody, /#EXT-X-KEY:METHOD=AES-128,URI="http:\/\/proxy\.test\/p\//);
    assert.match(variantBody, /http:\/\/proxy\.test\/p\//);

    const urls = variantBody
      .split('\n')
      .filter((line) => line.startsWith('http://proxy.test/p/'));
    assert.equal(urls.length, 2, 'two segments were rewritten');

    const segment = await call(new URL(urls[0]).pathname, env, ctx);
    assert.equal(segment.status, 200);
    assert.equal(segment.headers.get('content-type'), 'video/mp2t');
    assert.equal(segment.headers.get('access-control-allow-origin'), '*');
    assert.equal((await segment.arrayBuffer()).byteLength, 188);
    await ctx.flush();

    const requestsBefore = origin.state.requests.filter((path) => path === '/v1/seg0.ts').length;
    const cachedSegment = await call(new URL(urls[0]).pathname, env, ctx);
    assert.equal(cachedSegment.status, 200);
    assert.equal((await cachedSegment.arrayBuffer()).byteLength, 188);
    const requestsAfter = origin.state.requests.filter((path) => path === '/v1/seg0.ts').length;
    assert.equal(requestsAfter, requestsBefore, 'second segment request came from cache');

    const keyLine = variantBody
      .split('\n')
      .find((line) => line.startsWith('#EXT-X-KEY:'));
    const keyMatch = /URI="([^"]+)"/.exec(keyLine);
    assert.ok(keyMatch, 'key URI was rewritten');
    const keyResponse = await call(new URL(keyMatch[1]).pathname, env, ctx);
    assert.equal(keyResponse.status, 200);
    assert.equal((await keyResponse.arrayBuffer()).byteLength, 16);
    assert.ok(origin.state.requests.includes('/keys/k1.bin?x=1&y=2'), 'query string survived');
    await ctx.flush();
  } finally {
    await origin.close();
  }
});

test('supports byte ranges on file responses', async () => {
  const origin = await startMockOrigin();
  try {
    const ctx = makeContext();
    const env = makeEnv();
    const token = sign({
      u: origin.baseUrl + '/file.bin',
      r: 'https://embed.example/',
      k: 'file',
      e: Math.floor(Date.now() / 1000) + 60,
    });

    const response = await call('/p/' + token, env, ctx, { headers: { range: 'bytes=100-199' } });
    assert.equal(response.status, 206);
    assert.equal(response.headers.get('content-range'), 'bytes 100-199/1000');
    assert.equal((await response.arrayBuffer()).byteLength, 100);
  } finally {
    await origin.close();
  }
});

test('returns a clear error when an HLS URL serves HTML', async () => {
  const origin = await startMockOrigin();
  try {
    const ctx = makeContext();
    const token = sign({
      u: origin.baseUrl + '/page.html',
      r: 'https://embed.example/',
      k: 'hls',
      e: Math.floor(Date.now() / 1000) + 60,
    });
    const response = await call('/p/' + token, makeEnv(), ctx);
    assert.equal(response.status, 502);
    assert.match(await response.text(), /HTML instead of a playlist/);
  } finally {
    await origin.close();
  }
});

test('tokens produced by the PHP signer are accepted', async (t) => {
  const origin = await startMockOrigin();
  try {
    const php = process.env.PHP_BIN || 'php';
    const script = fileURLToPath(new URL('./php-token.php', import.meta.url));
    let output;
    try {
      output = execFileSync(php, [script, origin.baseUrl + '/master.m3u8'], {
        encoding: 'utf8',
        env: { ...process.env, PROXY_SECRET: SECRET },
      });
    } catch (error) {
      if (error && error.code === 'ENOENT') {
        t.skip('php is not available on PATH (set PHP_BIN to test this)');
        return;
      }
      throw error;
    }

    const tokenUrl = output.trim();
    assert.match(tokenUrl, /^http:\/\/proxy\.test\/p\//);
    const response = await call(new URL(tokenUrl).pathname, makeEnv(), makeContext());
    assert.equal(response.status, 200);
    assert.match(await response.text(), /^#EXTM3U/m);
  } finally {
    await origin.close();
  }
});
