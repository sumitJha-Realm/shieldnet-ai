const path = require('path');

function normalizeBackendUrl(rawUrl) {
  const fallback = 'http://localhost:8000';
  const value = (rawUrl || fallback).trim().replace(/\/$/, '');
  return value.replace(/\/api(?:\/v1)?$/, '');
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  outputFileTracingRoot: path.join(__dirname),
  transpilePackages: [
    '@leafygreen-ui/badge',
    '@leafygreen-ui/banner',
    '@leafygreen-ui/button',
    '@leafygreen-ui/card',
    '@leafygreen-ui/icon',
    '@leafygreen-ui/icon-button',
    '@leafygreen-ui/logo',
    '@leafygreen-ui/palette',
    '@leafygreen-ui/select',
    '@leafygreen-ui/side-nav',
    '@leafygreen-ui/table',
    '@leafygreen-ui/tabs',
    '@leafygreen-ui/text-input',
    '@leafygreen-ui/toggle',
    '@leafygreen-ui/tokens',
    '@leafygreen-ui/tooltip',
    '@leafygreen-ui/typography',
    '@leafygreen-ui/modal',
    '@leafygreen-ui/search-input',
    '@leafygreen-ui/toast',
  ],
  async rewrites() {
    const backendUrl = normalizeBackendUrl(process.env.NEXT_PUBLIC_API_URL);
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
