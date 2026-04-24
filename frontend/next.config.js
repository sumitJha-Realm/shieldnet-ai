/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
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
};

module.exports = nextConfig;
