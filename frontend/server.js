const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');
const { createProxyMiddleware } = require('http-proxy-middleware');

const dev = process.env.NODE_ENV !== 'production';
const hostname = '0.0.0.0';
const port = parseInt(process.env.PORT || '3000', 10);

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const apiProxy = createProxyMiddleware({
  target: BACKEND_URL,
  changeOrigin: true,
  pathRewrite: { '^/api': '/api' },
  logger: console,
});

app.prepare().then(() => {
  const server = createServer((req, res) => {
    const parsedUrl = parse(req.url, true);

    if (parsedUrl.pathname.startsWith('/api/')) {
      apiProxy(req, res);
    } else {
      handle(req, res, parsedUrl);
    }
  });

  server.listen(port, hostname, () => {
    console.log(`> ShieldNet AI frontend ready on http://${hostname}:${port}`);
    console.log(`> Proxying /api/* to ${BACKEND_URL}`);
  });
});
