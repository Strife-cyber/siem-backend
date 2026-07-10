/**
 * Production server wrapper for TanStack Start SSR.
 * Bridges the Web-API fetch handler (from dist/server/server.js)
 * to a standard Node.js HTTP server.
 *
 * Serves static assets from dist/client/ before falling through
 * to the SSR handler. Handles all edge cases:
 *  - Directories → skip to SSR
 *  - Non-existent files → skip to SSR
 *  - Binary streams → efficient pipe
 *  - Cache busting via hashed filenames → immutable cache headers
 */
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import server from './dist/server/server.js';

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';

// Resolve path to client build output
const __dirname = fileURLToPath(new URL('.', import.meta.url));
const CLIENT_DIR = join(__dirname, 'dist', 'client');

// MIME types for static assets
const MIME_TYPES = {
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.css': 'text/css',
  '.html': 'text/html',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.eot': 'application/vnd.ms-fontobject',
  '.json': 'application/json',
  '.map': 'application/json',
  '.txt': 'text/plain',
  '.xml': 'application/xml',
  '.pdf': 'application/pdf',
};

/**
 * Convert a Node.js IncomingMessage to a standard Web Request.
 */
function toWebRequest(req) {
  const protocol = req.socket?.encrypted ? 'https' : 'http';
  const host = req.headers.host || 'localhost';
  const url = `${protocol}://${host}${req.url}`;

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value) {
      if (Array.isArray(value)) {
        for (const v of value) headers.append(key, v);
      } else {
        headers.set(key, value);
      }
    }
  }

  // Read the request body
  const body =
    req.method !== 'GET' && req.method !== 'HEAD'
      ? new Promise((resolve, reject) => {
          const chunks = [];
          req.on('data', (chunk) => chunks.push(chunk));
          req.on('end', () => resolve(Buffer.concat(chunks)));
          req.on('error', reject);
        })
      : null;

  return new Request(url, {
    method: req.method,
    headers,
    body,
  });
}

/**
 * Write a Web Response to a Node.js ServerResponse.
 */
async function writeResponse(webRes, nodeRes) {
  // Flatten headers
  const headers = {};
  webRes.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') {
      if (!headers[key]) headers[key] = [];
      (Array.isArray(headers[key]) ? headers[key] : (headers[key] = [headers[key]])).push(value);
    } else {
      headers[key] = value;
    }
  });

  nodeRes.writeHead(webRes.status, headers);

  if (webRes.body) {
    const reader = webRes.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        nodeRes.write(value);
      }
    } catch (err) {
      console.error('Stream error:', err);
    } finally {
      reader.releaseLock();
    }
  }

  nodeRes.end();
}

// ───── HTTP Server ─────
const httpServer = createServer(async (req, res) => {
  try {
    // ── Serve static files from dist/client/ ──
    //   Only handle GET/HEAD requests for static files.
    //   Skip directories and non-existent files.
    if (req.method === 'GET' || req.method === 'HEAD') {
      const urlPath = new URL(req.url, 'http://localhost').pathname;
      const filePath = join(CLIENT_DIR, urlPath);

      // SECURITY: Prevent directory traversal attacks
      if (filePath.startsWith(CLIENT_DIR) && existsSync(filePath)) {
        const stats = statSync(filePath);
        if (stats.isFile()) {
          const ext = extname(filePath);
          const contentType = MIME_TYPES[ext] || 'application/octet-stream';
          const content = readFileSync(filePath);

          const responseHeaders = {
            'Content-Type': contentType,
            'Content-Length': stats.size,
          };

          // Hashed filenames (*.js, *.css with hash in name) can be cached forever
          if (/[_-][a-fA-F0-9]{8,}\./.test(urlPath)) {
            responseHeaders['Cache-Control'] = 'public, max-age=31536000, immutable';
          } else {
            responseHeaders['Cache-Control'] = 'public, max-age=3600';
          }

          res.writeHead(200, responseHeaders);
          res.end(content);
          return;
        }
        // If it's a directory, fall through to SSR (for SPA routing)
      }
    }

    // ── SSR handler ──
    const webReq = toWebRequest(req);
    const webRes = await server.fetch(webReq);
    await writeResponse(webRes, res);
  } catch (err) {
    console.error('Unhandled request error:', err);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
    }
    res.end('Internal Server Error');
  }
});

httpServer.listen(PORT, HOST);
await once(httpServer, 'listening');
console.log(`🚀 SSR server listening on http://${HOST}:${PORT}`);
