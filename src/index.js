/**
 * DivHard media proxy — Cloudflare Worker.
 *
 * Only handles media traffic, not the studio/admin. PHP signs a short-lived
 * token containing the upstream URL, the Referer to send, and the media kind.
 * The Worker verifies the HMAC, fetches the upstream, rewrites HLS playlists
 * so every child URL comes back through the Worker, and caches segments at
 * the edge.
 *
 * Token format (URL-safe, no padding):
 *   base64url(JSON payload) + "." + base64url(HMAC-SHA256(secret, payload))
 *
 * Payload: { u: upstreamUrl, r: referer, k: "hls"|"file"|"text"|"img", e: exp }
 */

const TOKEN_TTL = 86400;
const PLAYLIST_CACHE_SECONDS = 5;
const FILE_CACHE_SECONDS = 21600;
const TEXT_CACHE_SECONDS = 600;
const IMAGE_CACHE_SECONDS = 3600;

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, HEAD, OPTIONS',
  'access-control-allow-headers': 'Range, If-None-Match, If-Modified-Since',
  'access-control-expose-headers': 'Content-Length, Content-Range, Accept-Ranges, ETag',
  'access-control-max-age': '86400',
};

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: CORS });
      }

      if (url.pathname === '/' || url.pathname === '/health') {
        return json({ ok: true, service: 'divhard-media-proxy' });
      }

      if (url.pathname.startsWith('/p/')) {
        const token = url.pathname.slice('/p/'.length);
        return await handleProxy(token, request, env, ctx);
      }

      return text('Not found', 404);
    } catch (error) {
      return text('Proxy error: ' + (error && error.message ? error.message : String(error)), 500);
    }
  },
};

async function handleProxy(token, request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return text('Method not allowed', 405);
  }

  const secret = env.PROXY_SECRET;
  if (!secret || secret.length < 32) {
    return text('PROXY_SECRET is not configured. Run: npx wrangler secret put PROXY_SECRET', 500);
  }

  const payload = await verifyToken(token, secret);
  if (!payload) {
    return text('Invalid or expired media token', 403);
  }

  let upstreamUrl;
  try {
    upstreamUrl = new URL(payload.u);
  } catch {
    return text('Invalid upstream URL', 400);
  }
  if (upstreamUrl.protocol !== 'http:' && upstreamUrl.protocol !== 'https:') {
    return text('Invalid upstream scheme', 400);
  }
  if (env.ALLOW_PRIVATE_HOSTS !== '1' && isPrivateHostname(upstreamUrl.hostname)) {
    return text('Blocked upstream host', 403);
  }

  const kind = normaliseKind(payload.k, upstreamUrl.href);
  const referer = typeof payload.r === 'string' ? payload.r : '';
  const range = request.headers.get('range');
  const cache = caches.default;
  const cacheKey = await buildCacheKey(kind, upstreamUrl.href, referer);
  const cacheable = !range && request.method === 'GET' && kind !== 'hls';

  if (cacheable) {
    const hit = await cache.match(cacheKey);
    if (hit) {
      return withCors(hit);
    }
  }

  const headers = new Headers();
  headers.set('accept', '*/*');
  headers.set('accept-encoding', 'identity');
  headers.set('user-agent', USER_AGENT);
  if (referer) {
    headers.set('referer', referer);
    try {
      headers.set('origin', new URL(referer).origin);
    } catch {
      /* ignore malformed referer */
    }
  }
  if (range) {
    headers.set('range', range);
  }

  let upstream;
  try {
    upstream = await fetch(upstreamUrl.href, {
      method: request.method,
      headers,
      redirect: 'follow',
    });
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    return text('Upstream fetch failed: ' + message, 502);
  }

  if (upstream.status !== 200 && upstream.status !== 206 && upstream.status !== 304) {
    const status = upstream.status >= 400 && upstream.status <= 599 ? upstream.status : 502;
    const failed = text('Upstream returned ' + upstream.status, status);
    failed.headers.set('x-upstream-status', String(upstream.status));
    return failed;
  }

  if (kind === 'hls') {
    return await handlePlaylist(upstream, payload, request, env);
  }

  return await handleFile(upstream, kind, cacheable, cache, cacheKey, ctx);
}

async function handlePlaylist(upstream, payload, request, env) {
  const body = await upstream.text();
  const clean = body.replace(/^\uFEFF/, '').trimStart();

  if (!clean.startsWith('#EXTM3U')) {
    const looksHtml = clean.startsWith('<');
    return text(
      looksHtml ? 'Upstream returned HTML instead of a playlist' : 'Playlist could not be read',
      502
    );
  }

  const rewritten = await rewritePlaylist(
    body,
    upstream.url || payload.u,
    payload,
    request.url,
    env.PROXY_SECRET
  );

  const headers = new Headers(CORS);
  headers.set('content-type', 'application/vnd.apple.mpegurl; charset=utf-8');
  headers.set('cache-control', `public, max-age=${PLAYLIST_CACHE_SECONDS}`);
  headers.set('x-proxy-kind', 'hls');

  // Playlists are small and can be live, so they are proxied but not stored.
  return new Response(rewritten, { status: 200, headers });
}

async function handleFile(upstream, kind, cacheable, cache, cacheKey, ctx) {
  const headers = new Headers(CORS);
  for (const name of [
    'content-type',
    'content-range',
    'accept-ranges',
    'etag',
    'last-modified',
  ]) {
    const value = upstream.headers.get(name);
    if (value) {
      headers.set(name, value);
    }
  }

  if (!upstream.headers.get('content-encoding')) {
    const length = upstream.headers.get('content-length');
    if (length) {
      headers.set('content-length', length);
    }
  }

  if (!headers.has('accept-ranges')) {
    headers.set('accept-ranges', 'bytes');
  }

  const ttl =
    kind === 'img'
      ? IMAGE_CACHE_SECONDS
      : kind === 'text'
        ? TEXT_CACHE_SECONDS
        : FILE_CACHE_SECONDS;

  headers.set('x-proxy-kind', kind);
  headers.set('cache-control', cacheable ? `public, max-age=${ttl}` : 'no-store');

  const response = new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });

  if (cacheable && upstream.status === 200) {
    ctx.waitUntil(cache.put(cacheKey, response.clone()));
  }
  return response;
}

async function rewritePlaylist(body, baseUrl, payload, requestUrl, secret) {
  const origin = new URL(requestUrl).origin;
  const now = Math.floor(Date.now() / 1000);
  const parentExp = typeof payload.e === 'number' ? payload.e : now + TOKEN_TTL;
  const childExp = Math.max(Math.min(parentExp, now + TOKEN_TTL), now + 300);

  const makeUrl = async (reference) => {
    let absolute;
    try {
      absolute = new URL(decodeEntities(reference), baseUrl).href;
    } catch {
      return reference;
    }
    const childKind = isPlaylistUrl(absolute) ? 'hls' : payload.k === 'text' ? 'text' : 'file';
    const childToken = await signToken(
      { u: absolute, r: payload.r || '', k: childKind, e: childExp },
      secret
    );
    return origin + '/p/' + childToken;
  };

  const lines = body.split(/\r\n|\n|\r/);
  const out = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') {
      out.push('');
      continue;
    }

    if (trimmed.startsWith('#')) {
      let replaced = line;
      const matches = [...line.matchAll(/URI=(["'])(.*?)\1/gi)];
      for (const match of matches) {
        const proxied = await makeUrl(match[2]);
        replaced = replaced.replace(match[0], () => 'URI="' + proxied + '"');
      }
      out.push(replaced);
      continue;
    }

    out.push(await makeUrl(trimmed));
  }

  return out.join('\n') + '\n';
}

function normaliseKind(kind, url) {
  if (kind === 'hls' || kind === 'file' || kind === 'text' || kind === 'img') {
    return kind;
  }
  return isPlaylistUrl(url) ? 'hls' : 'file';
}

function isPlaylistUrl(url) {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();
    return path.endsWith('.m3u8') || path.endsWith('.m3u') || /\.m3u8?(\?|$)/i.test(url);
  } catch {
    return false;
  }
}

async function buildCacheKey(kind, url, referer) {
  const hash = await sha256Hex(kind + '\n' + url + '\n' + referer);
  return new Request('https://cache.divhard.internal/' + kind + '/' + hash, { method: 'GET' });
}

async function verifyToken(token, secret) {
  const dot = token.lastIndexOf('.');
  if (dot <= 0 || dot === token.length - 1) {
    return null;
  }

  const body = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = await hmacBase64(secret, body);
  if (!timingSafeEqual(signature, expected)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(body)));
  } catch {
    return null;
  }

  if (!payload || typeof payload.u !== 'string' || payload.u === '') {
    return null;
  }
  if (typeof payload.e === 'number' && payload.e < Math.floor(Date.now() / 1000)) {
    return null;
  }
  return payload;
}

async function signToken(payload, secret) {
  const body = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await hmacBase64(secret, body);
  return body + '.' + signature;
}

async function hmacBase64(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64UrlEncode(new Uint8Array(signature));
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value) {
  let normalised = value.replace(/-/g, '+').replace(/_/g, '/');
  while (normalised.length % 4 !== 0) {
    normalised += '=';
  }
  const binary = atob(normalised);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < left.length; i++) {
    diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return diff === 0;
}

function isPrivateHostname(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host === '0.0.0.0'
  ) {
    return true;
  }
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') {
    return true;
  }
  if (/^(fc|fd)[0-9a-f]{2}:/.test(host) || /^fe[89ab][0-9a-f]:/.test(host)) {
    return true;
  }
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)) {
    return true;
  }
  if (/^169\.254\./.test(host) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host)) {
    return true;
  }
  return false;
}

function decodeEntities(value) {
  return value
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#([0-9]+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)));
}

function withCors(response) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(CORS)) {
    headers.set(name, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function json(value, status = 200) {
  const headers = new Headers(CORS);
  headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(value), { status, headers });
}

function text(value, status = 200) {
  const headers = new Headers(CORS);
  headers.set('content-type', 'text/plain; charset=utf-8');
  return new Response(value, { status, headers });
}
