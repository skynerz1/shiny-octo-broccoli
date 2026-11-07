import http from 'node:http';

/**
 * Small HLS origin used by the local proxy tests. It covers:
 * - master playlist -> variant playlist
 * - relative and absolute segment URIs
 * - #EXT-X-KEY URI with HTML-escaped query string
 * - byte ranges
 * - an HTML error page for the "not a playlist" path
 */
export async function startMockOrigin() {
  const state = {
    requests: [],
    lastReferer: '',
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    state.requests.push(url.pathname + url.search);
    state.lastReferer = req.headers.referer || '';

    const referer = req.headers.referer || '';
    const key = Buffer.from('0123456789abcdef', 'utf8');
    const segment = Buffer.alloc(188, 0x47); // TS sync byte
    const file = Buffer.from(Array.from({ length: 1000 }, (_, i) => i % 251));

    if (url.pathname === '/master.m3u8') {
      res.writeHead(200, { 'content-type': 'application/vnd.apple.mpegurl' });
      res.end(
        [
          '#EXTM3U',
          `#MASTER-REFERER:${referer}`,
          '#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=1280x720',
          'v1/index.m3u8',
          '',
        ].join('\n')
      );
      return;
    }

    if (url.pathname === '/v1/index.m3u8') {
      res.writeHead(200, { 'content-type': 'application/vnd.apple.mpegurl' });
      res.end(
        [
          '#EXTM3U',
          '#EXT-X-VERSION:3',
          '#EXT-X-TARGETDURATION:4',
          '#EXT-X-KEY:METHOD=AES-128,URI="/keys/k1.bin?x=1&amp;y=2"',
          '#EXTINF:4.0,',
          'seg0.ts',
          '#EXTINF:4.0,',
          '/v1/seg1.ts',
          '#EXT-X-ENDLIST',
          '',
        ].join('\n')
      );
      return;
    }

    if (url.pathname === '/keys/k1.bin') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(key);
      return;
    }

    if (url.pathname === '/v1/seg0.ts' || url.pathname === '/v1/seg1.ts') {
      res.writeHead(200, { 'content-type': 'video/mp2t' });
      res.end(segment);
      return;
    }

    if (url.pathname === '/file.bin') {
      const range = req.headers.range;
      if (range) {
        const match = /^bytes=(\d+)-(\d+)$/.exec(range);
        if (match) {
          const start = Number(match[1]);
          const end = Math.min(Number(match[2]), file.length - 1);
          const slice = file.subarray(start, end + 1);
          res.writeHead(206, {
            'content-type': 'application/octet-stream',
            'content-range': `bytes ${start}-${end}/${file.length}`,
            'content-length': String(slice.length),
            'accept-ranges': 'bytes',
          });
          res.end(slice);
          return;
        }
      }
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-length': String(file.length),
        'accept-ranges': 'bytes',
      });
      res.end(file);
      return;
    }

    if (url.pathname === '/page.html') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><title>not a playlist</title>');
      return;
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    state,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
